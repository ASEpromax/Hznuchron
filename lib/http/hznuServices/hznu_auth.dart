import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:celechron/services/diagnostic_log_service.dart';
import '../zjuServices/exceptions.dart';
import '../zjuServices/response_utils.dart';

class _ActiveHznuSsoCookie {
  final Cookie cookie;
  final DateTime expiresAt;

  _ActiveHznuSsoCookie(this.cookie, this.expiresAt);
}

class _HznuLoginKey {
  final HttpClient httpClient;
  final String username;

  const _HznuLoginKey(this.httpClient, this.username);

  @override
  bool operator ==(Object other) =>
      other is _HznuLoginKey &&
      identical(httpClient, other.httpClient) &&
      username == other.username;

  @override
  int get hashCode => Object.hash(identityHashCode(httpClient), username);
}

/// 杭州师范大学统一身份认证（CAS）服务管理类。
/// 负责统一身份认证登录、SSO 会话管理及校园网连通性检测。
class HznuAuth {
  static const _secureStorage = FlutterSecureStorage();
  static const _processCookieLifetime = Duration(minutes: 5);
  static final Map<_HznuLoginKey, Future<Cookie?>> _pendingLogins = {};
  static final Map<_HznuLoginKey, _ActiveHznuSsoCookie> _activeCookies = {};

  /// 杭师大教务管理系统基地址
  static const String jwxtBaseUrl = 'http://jwxt.hznu.edu.cn';
  /// 杭师大统一身份认证基地址
  static const String casBaseUrl = 'https://auth.hznu.edu.cn';

  /// 检测当前网络环境是否能正常访问杭师大教务系统（判断是否需要校园网/VPN）
  static Future<({bool reachable, String message})> checkNetworkAvailability(
      HttpClient httpClient) async {
    try {
      final uri = Uri.parse('$jwxtBaseUrl/jwglxt/xtgl/login_sso.html');
      final request = await httpClient.getUrl(uri).timeout(
            const Duration(seconds: 5),
            onTimeout: () => throw const SocketException('连接杭师大教务系统超时'),
          );
      request.followRedirects = false;
      final response = await request.close().timeout(
            const Duration(seconds: 5),
            onTimeout: () => throw const SocketException('响应超时'),
          );
      // 无论是 200 还是 302 重定向至 CAS，均说明校园网络可达
      if (response.statusCode >= 200 && response.statusCode < 400) {
        return (reachable: true, message: '杭师大校园网络连接正常');
      }
      return (
        reachable: false,
        message: '教务系统服务响应异常 (HTTP ${response.statusCode})，可能正处于系统维护期'
      );
    } on SocketException catch (_) {
      return (
        reachable: false,
        message: '无法访问杭师大教务系统。若在校外，请连接校园 Wi-Fi 或开启学校 WebVPN 后重试。'
      );
    } on Object catch (e) {
      return (
        reachable: false,
        message: '网络检测失败：$e'
      );
    }
  }

  /// 获取或复用有效的 SSO Cookie
  static Future<Cookie?> getSsoCookie(
      HttpClient httpClient, String username, String password) async {
    final key = _HznuLoginKey(httpClient, username);
    final active = _activeSsoCookie(key);
    if (active != null) {
      return active;
    }

    final pending = _pendingLogins[key];
    if (pending != null) return await pending;

    final login = _doLogin(httpClient, username, password);
    _pendingLogins[key] = login;
    try {
      final cookie = await login;
      if (cookie != null) {
        _activeCookies[key] = _ActiveHznuSsoCookie(
          cookie,
          DateTime.now().add(_processCookieLifetime),
        );
      }
      return cookie;
    } finally {
      if (identical(_pendingLogins[key], login)) {
        _pendingLogins.remove(key);
      }
    }
  }

  static Cookie? _activeSsoCookie(_HznuLoginKey key) {
    final active = _activeCookies[key];
    if (active == null) return null;
    if (DateTime.now().isBefore(active.expiresAt)) {
      return active.cookie;
    }
    _activeCookies.remove(key);
    return null;
  }

  static Future<void> clearCachedSsoCookie(String username) async {
    _activeCookies.removeWhere((key, _) => key.username == username);
    await _secureStorage.delete(key: 'hznu_sso_cookie_$username');
  }

  /// 执行登录握手
  static Future<Cookie?> _doLogin(
      HttpClient httpClient, String username, String password) async {
    // 1. 先验证校园网可连通性
    final network = await checkNetworkAvailability(httpClient);
    if (!network.reachable) {
      throw LoginException(network.message);
    }

    try {
      // 2. 访问统一认证登录入口获取表单令牌
      final loginUri = Uri.parse('$jwxtBaseUrl/jwglxt/xtgl/login_sso.html');
      final request = await httpClient.getUrl(loginUri).timeout(
            const Duration(seconds: 8),
            onTimeout: () => throw requestTimeout('杭师大教务登录入口超时'),
          );
      request.followRedirects = false;
      final response = await request.close().timeout(
            const Duration(seconds: 8),
            onTimeout: () => throw requestTimeout('杭师大教务登录入口响应超时'),
          );

      // 如果有 302 重定向到 CAS
      final redirectLocation = response.headers.value(HttpHeaders.locationHeader);
      final targetUri = redirectLocation != null
          ? Uri.parse(redirectLocation.startsWith('http')
              ? redirectLocation
              : '$jwxtBaseUrl$redirectLocation')
          : loginUri;

      final loginPageReq = await httpClient.getUrl(targetUri).timeout(
            const Duration(seconds: 8),
            onTimeout: () => throw requestTimeout('统一身份认证页加载超时'),
          );
      loginPageReq.followRedirects = true;
      final loginPageResp = await loginPageReq.close().timeout(
            const Duration(seconds: 8),
            onTimeout: () => throw requestTimeout('统一身份认证页响应超时'),
          );

      final body = await readResponseBody(loginPageResp, context: '杭师大统一认证页');
      final cookies = List<Cookie>.from(loginPageResp.cookies);

      // 提取 execution 或 lt 令牌
      final execution = RegExp(r'name="execution" value="(.*?)"')
              .firstMatch(body)
              ?.group(1) ??
          RegExp(r'name="lt" value="(.*?)"').firstMatch(body)?.group(1);

      // 提交用户名与密码
      final postReq = await httpClient.postUrl(targetUri).timeout(
            const Duration(seconds: 8),
            onTimeout: () => throw requestTimeout('提交登录超时'),
          );
      postReq.followRedirects = false;
      postReq.headers.contentType =
          ContentType('application', 'x-www-form-urlencoded', charset: 'utf-8');
      postReq.cookies.addAll(cookies);

      final postData = <String, String>{
        'username': username,
        'password': password,
        '_eventId': 'submit',
      };
      if (execution != null) {
        postData['execution'] = execution;
      }

      postReq.add(utf8.encode(Uri(queryParameters: postData).query));
      final postResp = await postReq.close().timeout(
            const Duration(seconds: 8),
            onTimeout: () => throw requestTimeout('登录认证响应超时'),
          );

      // 检查下发 Cookie
      for (final cookie in postResp.cookies) {
        if (cookie.name.toLowerCase().contains('ticket') ||
            cookie.name == 'iPlanetDirectoryPro' ||
            cookie.name == 'CASTGC') {
          return cookie;
        }
      }

      // 允许任意带会话凭据的 Cookie
      if (postResp.cookies.isNotEmpty) {
        return postResp.cookies.first;
      }

      // 如果 302 成功重定向回到教务
      final postLocation = postResp.headers.value(HttpHeaders.locationHeader);
      if (postResp.isRedirect && postLocation != null && postLocation.contains('ticket')) {
        return Cookie('hznu_ticket', postLocation);
      }

      throw LoginException('杭师大统一身份认证失败：请核对学号或密码是否正确。');
    } on LoginException {
      rethrow;
    } on Object catch (error, stackTrace) {
      DiagnosticLogService.instance.record(
        level: CelechronLogLevel.error,
        module: 'HznuAuth',
        operation: 'login',
        error: error,
        stackTrace: stackTrace,
      );
      throw LoginException('杭师大认证异常：$error');
    }
  }
}

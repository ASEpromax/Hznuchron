import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:encrypt/encrypt.dart' as enc;
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

/// 杭州师范大学金智统一身份认证（Authserver）服务管理类。
/// 实现了官方前端 AES-128-CBC 动态加盐加密认证握手与 SSO 会话管理。
class HznuAuth {
  static const _secureStorage = FlutterSecureStorage();
  static const _processCookieLifetime = Duration(minutes: 5);
  static final Map<_HznuLoginKey, Future<Cookie?>> _pendingLogins = {};
  static final Map<_HznuLoginKey, _ActiveHznuSsoCookie> _activeCookies = {};

  /// 杭师大教务管理系统基地址
  static const String jwxtBaseUrl = 'http://jwxt.hznu.edu.cn';
  /// 杭师大统一身份认证基地址
  static const String casBaseUrl = 'https://authserver.hznu.edu.cn';
  /// 附带教务 SSO 回调服务的统一认证登录入口
  static const String casServiceLoginUrl =
      '$casBaseUrl/authserver/login?service=$jwxtBaseUrl/jwglxt/xtgl/login_sso.html';

  static const String _aesChars =
      'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678';

  /// 生成随机指定长度混淆字符串（与官方 encrypt.js randomString 算法一致）
  static String _randomString(int length) {
    final rnd = Random();
    return List.generate(
      length,
      (_) => _aesChars[rnd.nextInt(_aesChars.length)],
    ).join();
  }

  /// 杭师大官方 AES-128-CBC 动态加盐加密算法
  static String _encryptPassword(String password, String salt) {
    final cleanSalt = salt.trim();
    if (cleanSalt.isEmpty) return password;
    final plainText = _randomString(64) + password;
    final ivStr = _randomString(16);

    final key = enc.Key.fromUtf8(cleanSalt);
    final iv = enc.IV.fromUtf8(ivStr);
    final encrypter = enc.Encrypter(
      enc.AES(key, mode: enc.AESMode.cbc, padding: 'PKCS7'),
    );
    final encrypted = encrypter.encrypt(plainText, iv: iv);
    return encrypted.base64;
  }

  /// 检测当前网络环境是否能正常访问杭师大统一认证中心
  static Future<({bool reachable, String message})> checkNetworkAvailability(
      HttpClient httpClient) async {
    try {
      final uri = Uri.parse(casServiceLoginUrl);
      final request = await httpClient.getUrl(uri).timeout(
            const Duration(seconds: 8),
            onTimeout: () => throw const SocketException('连接杭师大认证中心超时'),
          );
      request.followRedirects = true;
      final response = await request.close().timeout(
            const Duration(seconds: 8),
            onTimeout: () => throw const SocketException('响应超时'),
          );
      if (response.statusCode >= 200 && response.statusCode < 400) {
        return (reachable: true, message: '杭师大统一认证服务连接正常');
      }
      return (
        reachable: false,
        message: '统一认证服务响应异常 (HTTP ${response.statusCode})，可能正处于系统维护期'
      );
    } on SocketException catch (_) {
      return (
        reachable: false,
        message: '无法访问杭师大统一认证中心，请检查手机网络连接。'
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

  /// 执行认证握手
  static Future<Cookie?> _doLogin(
      HttpClient httpClient, String username, String password) async {
    // 1. 网络探活
    final network = await checkNetworkAvailability(httpClient);
    if (!network.reachable) {
      throw LoginException(network.message);
    }

    try {
      // 2. 访问统一认证入口，获取 execution、lt 与动态 pwdEncryptSalt 盐值
      final loginUri = Uri.parse(casServiceLoginUrl);
      final req1 = await httpClient.getUrl(loginUri).timeout(
            const Duration(seconds: 8),
            onTimeout: () => throw requestTimeout('杭师大统一认证页面加载超时'),
          );
      req1.followRedirects = true;
      final resp1 = await req1.close().timeout(
            const Duration(seconds: 8),
            onTimeout: () => throw requestTimeout('杭师大统一认证入口响应超时'),
          );

      final body1 = await readResponseBody(resp1, context: '杭师大统一认证页');
      final cookies = List<Cookie>.from(resp1.cookies);

      // 提取 execution 流程令牌
      final execution = RegExp(r'name="execution"\s+value="(.*?)"')
              .firstMatch(body1)
              ?.group(1) ??
          RegExp(r'id="execution"\s+value="(.*?)"').firstMatch(body1)?.group(1);

      // 提取动态 AES 加密盐值
      final salt = RegExp(r'id="pwdEncryptSalt"\s+value="(.*?)"')
              .firstMatch(body1)
              ?.group(1) ??
          RegExp(r'name="pwdEncryptSalt"\s+value="(.*?)"').firstMatch(body1)?.group(1);

      // 提取 lt 令牌
      final lt = RegExp(r'name="lt"\s+value="(.*?)"')
          .firstMatch(body1)
          ?.group(1);

      if (execution == null) {
        // 若没有表单 execution，检查是否已经属于登录状态
        for (final cookie in cookies) {
          if (cookie.name == 'CASTGC' || cookie.name.contains('ticket')) {
            return cookie;
          }
        }
        throw LoginException('未能获取杭师大统一认证登录令牌，请稍后重试。');
      }

      // 3. 对密码执行 AES 动态加密
      final String encryptedPassword;
      if (salt != null && salt.isNotEmpty) {
        encryptedPassword = _encryptPassword(password, salt);
      } else {
        encryptedPassword = password;
      }

      // 4. 提交登录表单
      final postReq = await httpClient.postUrl(loginUri).timeout(
            const Duration(seconds: 8),
            onTimeout: () => throw requestTimeout('提交杭师大认证超时'),
          );
      postReq.followRedirects = false; // 拦截 302 重定向以截获 ticket
      postReq.headers.contentType =
          ContentType('application', 'x-www-form-urlencoded', charset: 'utf-8');
      postReq.headers.add('User-Agent',
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36');
      postReq.headers.add('Referer', casServiceLoginUrl);
      postReq.cookies.addAll(cookies);

      final postData = <String, String>{
        'username': username,
        'password': encryptedPassword,
        '_eventId': 'submit',
        'cllt': 'userNameLogin',
        'dllt': 'generalLogin',
        'execution': execution,
      };
      if (lt != null && lt.isNotEmpty) {
        postData['lt'] = lt;
      }

      postReq.add(utf8.encode(Uri(queryParameters: postData).query));
      final postResp = await postReq.close().timeout(
            const Duration(seconds: 8),
            onTimeout: () => throw requestTimeout('杭师大认证响应超时'),
          );

      // 5. 判断认证成功
      // A. 服务端 302 重定向回到教务，带有 ticket=ST-...
      final redirectLocation =
          postResp.headers.value(HttpHeaders.locationHeader);
      if (postResp.isRedirect && redirectLocation != null) {
        if (redirectLocation.contains('ticket') ||
            redirectLocation.contains('login_sso')) {
          return Cookie('hznu_ticket', redirectLocation);
        }
      }

      // B. 服务端下发了 CASTGC 会话凭据
      for (final cookie in postResp.cookies) {
        if (cookie.name == 'CASTGC') {
          return cookie;
        }
      }

      // C. 检查表单报错提示
      final failBody = await readResponseBody(postResp, context: '杭师大认证结果');
      final errorMatch = RegExp(r'id="showErrorTip"[^>]*>(.*?)<')
              .firstMatch(failBody)
              ?.group(1)
              ?.trim() ??
          RegExp(r'class="form-error"[^>]*>(.*?)<')
              .firstMatch(failBody)
              ?.group(1)
              ?.trim();

      if (errorMatch != null && errorMatch.isNotEmpty) {
        throw LoginException('杭师大统一认证失败：$errorMatch');
      }

      if (failBody.contains('验证码') || failBody.contains('captcha')) {
        throw LoginException('触发了安全验证码保护，请先在手机浏览器登录一次该账号后重试。');
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

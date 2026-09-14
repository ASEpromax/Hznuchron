import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart';

import 'package:celechron/database/database_helper.dart';
import 'package:celechron/model/grade.dart';
import 'package:celechron/model/session.dart';
import 'package:celechron/model/exams_dto.dart';
import 'package:celechron/utils/tuple.dart';
import 'package:celechron/utils/gpa_helper.dart';
import 'package:celechron/services/diagnostic_log_service.dart';
import '../zjuServices/exceptions.dart';
import '../zjuServices/response_utils.dart';

/// 杭州师范大学正方教务系统（jwxt.hznu.edu.cn）客户端。
/// 管理教务会话（JSESSIONID）、课表拉取、成绩与考试查询及本地缓存容灾。
class HznuJwxt {
  static const String jwxtBaseUrl = 'http://jwxt.hznu.edu.cn';

  Cookie? _jSessionId;
  Cookie? _route;
  Cookie? _ssoCookie;
  DatabaseHelper? _db;
  Future<bool>? _loginFuture;
  int _sessionGeneration = 0;
  int timetableRawRowsForDiagnostics = 0;

  set db(DatabaseHelper? db) {
    _db = db;
  }

  bool get isLoggedIn => _jSessionId != null;

  void logout() {
    _jSessionId = null;
    _route = null;
    _ssoCookie = null;
  }

  Future<bool> login(HttpClient httpClient, Cookie? ssoCookie) async {
    if (ssoCookie == null) {
      throw AuthenticationExpiredException("杭师大教务：统一身份认证凭据为空");
    }
    _ssoCookie = ssoCookie;
    final pending = _loginFuture;
    if (pending != null) return await pending;

    final loginTask = _doLogin(httpClient, ssoCookie);
    _loginFuture = loginTask;
    try {
      return await loginTask;
    } finally {
      if (identical(_loginFuture, loginTask)) _loginFuture = null;
    }
  }

  Future<bool> _doLogin(HttpClient httpClient, Cookie ssoCookie) async {
    _jSessionId = null;
    _route = null;

    final ssoLoginUrl = Uri.parse(
        "$jwxtBaseUrl/jwglxt/xtgl/login_sso.html");

    final request = await httpClient.getUrl(ssoLoginUrl).timeout(
          const Duration(seconds: 8),
          onTimeout: () => throw requestTimeout('杭师大教务 SSO 登录超时'),
        );
    request.followRedirects = false;
    request.cookies.add(ssoCookie);

    final response = await request.close().timeout(
          const Duration(seconds: 8),
          onTimeout: () => throw requestTimeout('杭师大教务 SSO 响应超时'),
        );

    for (final cookie in response.cookies) {
      if (cookie.name == 'JSESSIONID') {
        _jSessionId = cookie;
      } else if (cookie.name == 'route') {
        _route = cookie;
      }
    }

    // 如果返回 302 重定向
    if (response.isRedirect) {
      var location = response.headers.value(HttpHeaders.locationHeader);
      if (location != null) {
        final redirectUri = Uri.parse(
            location.startsWith('http') ? location : '$jwxtBaseUrl$location');
        final redReq = await httpClient.getUrl(redirectUri).timeout(
              const Duration(seconds: 8),
              onTimeout: () => throw requestTimeout(),
            );
        redReq.followRedirects = false;
        if (_jSessionId != null) redReq.cookies.add(_jSessionId!);
        if (_route != null) redReq.cookies.add(_route!);

        final redResp = await redReq.close().timeout(
              const Duration(seconds: 8),
              onTimeout: () => throw requestTimeout(),
            );

        for (final cookie in redResp.cookies) {
          if (cookie.name == 'JSESSIONID') {
            _jSessionId = cookie;
          } else if (cookie.name == 'route') {
            _route = cookie;
          }
        }
      }
    }

    if (_jSessionId == null) {
      throw ExceptionWithMessage("杭师大教务登录未能获取 JSESSIONID 会话凭据");
    }

    _sessionGeneration++;
    return true;
  }

  /// 封装教务请求并附加 Cookies
  Future<HttpClientRequest> _openRequest(
      HttpClient httpClient, String method, Uri uri) async {
    HttpClientRequest request;
    if (method == 'POST') {
      request = await httpClient.postUrl(uri);
    } else {
      request = await httpClient.getUrl(uri);
    }
    request.followRedirects = false;
    if (_jSessionId != null) request.cookies.add(_jSessionId!);
    if (_route != null) request.cookies.add(_route!);
    request.headers
      ..add("Referer", "$jwxtBaseUrl/jwglxt/xtgl/index_initMenu.html")
      ..set('Connection', 'close')
      ..add('User-Agent',
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36')
      ..add('Accept', 'application/json, text/javascript, */*; q=0.01')
      ..add('X-Requested-With', 'XMLHttpRequest');
    return request;
  }

  /// 获取课表（带 Tuple 返回值与容灾读取）
  Future<Tuple<Exception?, Iterable<Session>>> getTimetable(
    HttpClient httpClient,
    String year,
    String semester,
  ) async {
    final cacheKey = 'hznu_timetable_${year}_$semester';
    final uri = Uri.parse('$jwxtBaseUrl/jwglxt/kbcx/xskbcx_cxXsKb.html');

    try {
      final request = await _openRequest(httpClient, 'POST', uri);
      request.headers.contentType =
          ContentType('application', 'x-www-form-urlencoded', charset: 'utf-8');

      final postBody = <String, String>{
        'xnm': year,
        'xqm': semester,
      };
      request.add(utf8.encode(Uri(queryParameters: postBody).query));

      final response = await request.close().timeout(
            const Duration(seconds: 10),
            onTimeout: () => throw requestTimeout('杭师大课表获取超时'),
          );

      final body = await readResponseBody(response, context: '杭师大课表查询');
      final jsonMap = decodeJsonMap(body, context: '杭师大课表响应');

      final kbList = jsonMap['kbList'] as List<dynamic>? ?? [];
      timetableRawRowsForDiagnostics = kbList.length;

      final sessions = <Session>[];
      for (final item in kbList) {
        if (item is Map<String, dynamic>) {
          try {
            sessions.add(Session.fromZdbk(item));
          } catch (e) {
            if (kDebugMode) {
              debugPrint('解析单门课程异常: $e');
            }
          }
        }
      }

      if (sessions.isNotEmpty) {
        _writeCache(cacheKey, body);
      }
      return Tuple(null, sessions);
    } on Object catch (error, stackTrace) {
      final cached = _db?.getCachedWebPage(cacheKey);
      if (cached != null && cached.isNotEmpty) {
        try {
          final jsonMap = decodeJsonMap(cached, context: '课表缓存');
          final kbList = jsonMap['kbList'] as List<dynamic>? ?? [];
          final cachedSessions = kbList
              .whereType<Map<String, dynamic>>()
              .map((e) => Session.fromZdbk(e))
              .toList();
          return Tuple(
            CachedDataException('杭师大课表实时获取失败，已回退至本地缓存',
                originalError: error, stackTrace: stackTrace),
            cachedSessions,
          );
        } catch (_) {}
      }
      return Tuple(
        exceptionFrom(error, context: '杭师大课表', requestUri: uri, stackTrace: stackTrace),
        const [],
      );
    }
  }

  /// 获取成绩单
  Future<Tuple<Exception?, Iterable<Grade>>> getTranscript(
      HttpClient httpClient) async {
    const cacheKey = 'hznu_transcript_cache';
    final uri = Uri.parse(
        '$jwxtBaseUrl/jwglxt/cxdy/xscjcx_cxXscjIndex.html?doType=query&queryModel.showCount=5000');

    try {
      final request = await _openRequest(httpClient, 'POST', uri);
      final response = await request.close().timeout(
            const Duration(seconds: 10),
            onTimeout: () => throw requestTimeout('杭师大成绩查询超时'),
          );

      final body = await readResponseBody(response, context: '杭师大成绩查询');
      final jsonMap = decodeJsonMap(body, context: '杭师大成绩响应');
      final items = jsonMap['items'] as List<dynamic>? ?? [];

      final grades = <Grade>[];
      for (final item in items) {
        if (item is Map<String, dynamic>) {
          grades.add(Grade.fromZdbk(item));
        }
      }

      if (grades.isNotEmpty) {
        _writeCache(cacheKey, body);
      }
      return Tuple(null, grades);
    } on Object catch (error, stackTrace) {
      final cached = _db?.getCachedWebPage(cacheKey);
      if (cached != null && cached.isNotEmpty) {
        try {
          final jsonMap = decodeJsonMap(cached, context: '成绩缓存');
          final items = jsonMap['items'] as List<dynamic>? ?? [];
          final cachedGrades = items
              .whereType<Map<String, dynamic>>()
              .map((e) => Grade.fromZdbk(e))
              .toList();
          return Tuple(
            CachedDataException('杭师大成绩获取失败，已使用本地缓存',
                originalError: error, stackTrace: stackTrace),
            cachedGrades,
          );
        } catch (_) {}
      }
      return Tuple(
        exceptionFrom(error, context: '杭师大成绩', requestUri: uri, stackTrace: stackTrace),
        const [],
      );
    }
  }

  /// 获取主修成绩
  Future<Tuple<Exception?, Tuple<List<double>, String>>> getMajorGrade(
      HttpClient httpClient) async {
    const cacheKey = 'hznu_major_grade_cache';
    final uri = Uri.parse(
        '$jwxtBaseUrl/jwglxt/zycjtj/xszgkc_cxXsZgkcIndex.html?doType=query&queryModel.showCount=5000');

    try {
      final request = await _openRequest(httpClient, 'POST', uri);
      final response = await request.close().timeout(
            const Duration(seconds: 10),
            onTimeout: () => throw requestTimeout('杭师大主修成绩超时'),
          );

      final body = await readResponseBody(response, context: '杭师大主修成绩');
      final jsonMap = decodeJsonMap(body, context: '杭师大主修成绩响应');
      final items = jsonMap['items'] as List<dynamic>? ?? [];

      final grades = <Grade>[];
      for (final item in items) {
        if (item is Map<String, dynamic>) {
          grades.add(Grade.fromZdbk(item, major: true));
        }
      }

      final majorGpa = GpaHelper.calculateGpa(grades);
      _writeCache(cacheKey, body);
      return Tuple(null, Tuple([majorGpa.item1[0], majorGpa.item2], body));
    } on Object catch (error, stackTrace) {
      final cached = _db?.getCachedWebPage(cacheKey);
      if (cached != null && cached.isNotEmpty) {
        try {
          final jsonMap = decodeJsonMap(cached, context: '主修成绩缓存');
          final items = jsonMap['items'] as List<dynamic>? ?? [];
          final grades = items
              .whereType<Map<String, dynamic>>()
              .map((e) => Grade.fromZdbk(e, major: true))
              .toList();
          final majorGpa = GpaHelper.calculateGpa(grades);
          return Tuple(
            CachedDataException('杭师大主修成绩使用本地缓存',
                originalError: error, stackTrace: stackTrace),
            Tuple([majorGpa.item1[0], majorGpa.item2], cached),
          );
        } catch (_) {}
      }
      return Tuple(
        exceptionFrom(error, context: '杭师大主修成绩', requestUri: uri, stackTrace: stackTrace),
        Tuple([0.0, 0.0], '{}'),
      );
    }
  }

  /// 获取考试日程
  Future<Tuple<Exception?, Iterable<ExamDto>>> getExamsDto(
      HttpClient httpClient) async {
    final uri = Uri.parse(
        '$jwxtBaseUrl/jwglxt/xskscx/kscx_cxXsgrksIndex.html?doType=query&queryModel.showCount=5000');

    try {
      final request = await _openRequest(httpClient, 'POST', uri);
      final response = await request.close().timeout(
            const Duration(seconds: 10),
            onTimeout: () => throw requestTimeout('杭师大考试查询超时'),
          );

      final body = await readResponseBody(response, context: '杭师大考试查询');
      final jsonMap = decodeJsonMap(body, context: '杭师大考试响应');
      final items = jsonMap['items'] as List<dynamic>? ?? [];

      final examsDto = ExamsDto.fromZdbk(items);
      return Tuple(null, examsDto.item2);
    } on Object catch (error, stackTrace) {
      return Tuple(
        exceptionFrom(error, context: '杭师大考试', requestUri: uri, stackTrace: stackTrace),
        const [],
      );
    }
  }

  void _writeCache(String cacheKey, String value) {
    unawaited(Future.wait([
      _db?.setCachedWebPage(cacheKey, value) ?? Future<void>.value(),
      _db?.setCachedWebPage(
            '${cacheKey}_timestamp',
            DateTime.now().toUtc().toIso8601String(),
          ) ??
          Future<void>.value(),
    ]));
  }
}

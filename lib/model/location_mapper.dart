class CampusAlias {
  final String campusName;
  final List<String> aliases;

  const CampusAlias({
    required this.campusName,
    required this.aliases,
  });
}

class BuildingAlias {
  final String? campusName;
  final List<String> aliases;
  final String fullName;

  const BuildingAlias({
    this.campusName,
    required this.aliases,
    required this.fullName,
  });
}

/// 日历地点映射器
/// 将教务系统中的上课地址缩写转换为详细地址，便于日历和导航识别。
/// 杭州师范大学主要校区：仓前校区、下沙校区、玉皇山校区。
class CalendarLocationMapper {
  static const List<CampusAlias> _campusAliases = [
    CampusAlias(campusName: '仓前', aliases: ['仓前', '仓前校区']),
    CampusAlias(campusName: '下沙', aliases: ['下沙', '下沙校区']),
    CampusAlias(campusName: '玉皇山', aliases: ['玉皇山', '玉皇山校区']),
  ];

  /// 楼宇映射表：恕园、诚园、勤园、慎园等
  static const List<BuildingAlias> _buildingAliases = [
    // 仓前校区
    BuildingAlias(campusName: '仓前', aliases: ['恕1', '恕园1', '恕园1号楼'], fullName: '恕园1号楼'),
    BuildingAlias(campusName: '仓前', aliases: ['恕2', '恕园2', '恕园2号楼'], fullName: '恕园2号楼'),
    BuildingAlias(campusName: '仓前', aliases: ['恕3', '恕园3', '恕园3号楼'], fullName: '恕园3号楼'),
    BuildingAlias(campusName: '仓前', aliases: ['恕4', '恕园4', '恕园4号楼'], fullName: '恕园4号楼'),
    BuildingAlias(campusName: '仓前', aliases: ['恕5', '恕园5', '恕园5号楼'], fullName: '恕园5号楼'),
    BuildingAlias(campusName: '仓前', aliases: ['恕6', '恕园6', '恕园6号楼'], fullName: '恕园6号楼'),
    BuildingAlias(campusName: '仓前', aliases: ['恕7', '恕园7', '恕园7号楼'], fullName: '恕园7号楼'),
    BuildingAlias(campusName: '仓前', aliases: ['恕8', '恕园8', '恕园8号楼'], fullName: '恕园8号楼'),
    BuildingAlias(campusName: '仓前', aliases: ['恕9', '恕园9', '恕园9号楼'], fullName: '恕园9号楼'),
    BuildingAlias(campusName: '仓前', aliases: ['恕10', '恕园10', '恕园10号楼'], fullName: '恕园10号楼'),
    BuildingAlias(campusName: '仓前', aliases: ['诚1', '诚园1', '诚园1号楼'], fullName: '诚园1号楼'),
    BuildingAlias(campusName: '仓前', aliases: ['诚2', '诚园2', '诚园2号楼'], fullName: '诚园2号楼'),
    BuildingAlias(campusName: '仓前', aliases: ['诚3', '诚园3', '诚园3号楼'], fullName: '诚园3号楼'),
    BuildingAlias(campusName: '仓前', aliases: ['诚4', '诚园4', '诚园4号楼'], fullName: '诚园4号楼'),
    BuildingAlias(campusName: '仓前', aliases: ['勤1', '勤园1', '勤园1号楼'], fullName: '勤园1号楼'),
    BuildingAlias(campusName: '仓前', aliases: ['慎1', '慎园1', '慎园1号楼'], fullName: '慎园1号楼'),
    BuildingAlias(campusName: '仓前', aliases: ['博文', '博文苑'], fullName: '博文苑'),
  ];

  static String mapForCalendar(String? rawLocation) {
    if (rawLocation == null) return '';
    final raw = rawLocation.trim();
    if (raw.isEmpty) return '';

    final normalized = _normalizeDash(raw);
    final parts = _splitHeadAndRoom(normalized);

    String? mappedAddress;
    if (parts == null) {
      // 无房间号，直接映射整体
      mappedAddress = _mapHeadToFullAddress(normalized);
    } else {
      final head = parts.$1;
      if (head.isEmpty) return raw;

      final mappedHead = _mapHeadToFullAddress(head);
      if (mappedHead != null) {
        mappedAddress = mappedHead;
      }
    }

    if (mappedAddress == null) return raw;
    return '$normalized, $mappedAddress';
  }

  static String? _mapHeadToFullAddress(String head) {
    final campus = _matchCampus(head);
    if (campus == null) return null;

    final buildingRaw = _stripCampusAlias(head, campus).trim();
    if (buildingRaw.isEmpty) {
      return '杭州师范大学${campus.campusName}校区';
    }

    final buildingName = _mapBuildingName(campus.campusName, buildingRaw);
    return '杭州师范大学${campus.campusName}校区$buildingName';
  }

  static CampusAlias? _matchCampus(String raw) {
    for (final campus in _campusAliases) {
      for (final alias in campus.aliases) {
        if (raw.contains(alias)) return campus;
      }
    }
    return null;
  }

  static String _stripCampusAlias(String raw, CampusAlias campus) {
    var result = raw;
    for (final alias in campus.aliases) {
      result = result.replaceFirst(alias, '');
    }
    return result;
  }

  static String _mapBuildingName(String campusName, String buildingRaw) {
    // 映射表
    for (final item in _buildingAliases) {
      if (item.campusName != null && item.campusName != campusName) continue;
      if (item.aliases.contains(buildingRaw)) return item.fullName;
    }

    // 未命中，保留原始文本
    return buildingRaw;
  }

  static (String, String)? _splitHeadAndRoom(String raw) {
    final dashIndex = raw.indexOf('-');
    if (dashIndex == -1) return null;
    final head = raw.substring(0, dashIndex).trim();
    final room = raw.substring(dashIndex + 1).trim();
    return (head, room);
  }

  static String _normalizeDash(String raw) {
    return raw
        .replaceAll('－', '-')
        .replaceAll('—', '-')
        .replaceAll('–', '-')
        .replaceAll('−', '-');
  }
}

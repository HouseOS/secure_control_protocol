/*
secure_control_protocol
ScpResponseDiscover Class
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

// SCP
import 'package:secure_control_protocol/scp.dart';
import 'package:secure_control_protocol/scp_crypto.dart';
import 'package:secure_control_protocol/scp_device.dart';
import 'package:secure_control_protocol/util/utils.dart';

class ScpResponseDiscover {
  static const String type = "discover-response";
  String deviceId;
  String deviceType;
  String deviceName;
  int currentPasswordNumber;
  String hmac;
  List<String> controlActions;
  List<String> measureActions;

  ScpResponseDiscover(
      {this.deviceId,
      this.deviceType,
      this.deviceName,
      this.currentPasswordNumber,
      this.hmac,
      this.controlActions,
      this.measureActions});

  /// Returns a ScpResponseDiscover if HMAC valid, otherwise null
  factory ScpResponseDiscover.fromJson(
      var json, List<ScpDevice> devices, bool verifyHmac) {
    Scp.getInstance().log('$json');
    if (json['type'] == type) {
      if (json['deviceId'] == null ||
          json['deviceId'] == '' ||
          json['deviceType'] == null ||
          json['deviceType'] == '' ||
          json['currentPasswordNumber'] == null ||
          json['currentPasswordNumber'] == '' ||
          json['hmac'] == null ||
          json['hmac'] == '') {
        return null;
      }

      ScpResponseDiscover discoverResponse = ScpResponseDiscover(
        deviceId: json['deviceId'],
        deviceType: json['deviceType'],
        deviceName: json['deviceName'] != null ? json['deviceName'] : '',
        controlActions: json['controlActions'] != null
            ? Utils.dynamicListToStringList(json['controlActions'])
            : null,
        measureActions: json['measureActions'] != null
            ? Utils.dynamicListToStringList(json['measureActions'])
            : null,
        currentPasswordNumber: int.parse(json['currentPasswordNumber']),
        hmac: json['hmac'],
      );

      String password = null;
      if (devices != null && devices.length > 0) {
        password = devices
            .firstWhere(
                (element) => element.deviceId == discoverResponse.deviceId)
            .knownPassword;
      }

      // Check hmac before additional processing
      if (verifyHmac) {
        String controlActions = '';
        if (discoverResponse.controlActions != null) {
          for (String s in discoverResponse.controlActions) {
            controlActions += '"$s"';
          }
        }
        String measureActions = '';
        if (discoverResponse.measureActions != null) {
          for (String s in discoverResponse.measureActions) {
            measureActions += '"$s"';
          }
        }
        String verifyString =
            '${ScpResponseDiscover.type}${discoverResponse.deviceId}${discoverResponse.deviceType}${discoverResponse.deviceName}${controlActions}${measureActions}${discoverResponse.currentPasswordNumber}';
        Scp.getInstance().log('verify string:');
        Scp.getInstance().log(verifyString);
        if (ScpCrypto()
            .verifyHMAC(verifyString, discoverResponse.hmac, password)) {
          return discoverResponse;
        }
      } else {
        return discoverResponse;
      }
    }
    return null;
  }
}

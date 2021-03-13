/*
secure_control_protocol
Scp Main Class
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

// Standard Library
import 'dart:async';
import 'dart:convert';
import 'dart:io';

// SCP
import 'package:secure_control_protocol/scp_response_parser.dart';
import 'package:secure_control_protocol/scp_responses/scp_response_measure.dart';
import 'package:secure_control_protocol/scp_status.dart';
import 'package:secure_control_protocol/scp_message_sender.dart';
import 'package:secure_control_protocol/scp_device.dart';

// SCP Responses
import 'package:secure_control_protocol/scp_responses/scp_response_discover.dart';

// SCP Util
import 'package:secure_control_protocol/util/ip_range.dart';
import 'package:secure_control_protocol/util/json_storage.dart';

class Scp {
  static Scp instance;

  // List of configured devices known to SCP
  List<ScpDevice> knownDevices;

  // List of newly discovered not configured devices
  List<ScpDevice> newDevices;

  //Logging
  bool loggingEnabled = false;

  static Scp getInstance() {
    if (Scp.instance == null) {
      Scp.instance = Scp();
    }
    return Scp.instance;
  }

  Scp() {
    knownDevices = List<ScpDevice>.empty(growable: true);
  }

  void enableLogging() {
    loggingEnabled = true;
  }

  void log(String s) {
    print('$s');
  }

  // Initialize knownDevices from JSON
  void knownDevicesFromJson(var json) {
    knownDevices = ScpDevice.devicesfromJson(json);
  }

  void knownDevicesFromFile(File file) async {
    // Read the file
    String contents = await file.readAsString();
    var jsonString = json.decode(contents);
    knownDevicesFromJson(jsonString);
  }

  void doDiscover(String subnet, String mask) async {
    newDevices = List<ScpDevice>.empty(growable: true);
    // Get a list with all relevant IP addresses
    IPRange range = IPRange(subnet, int.parse(mask));
    List<String> allIPs = range.getAllIpAddressesInRange();

    List<Future> requests = List<Future>.empty(growable: true);

    await allIPs.forEach((ip) async {
      requests.add(ScpMessageSender.sendDiscoverHello(ip));
    });

    await Future.wait(requests).then(
        (List responses) => responses.forEach((response) {
              if (response != null && response.bodyBytes != null) {
                if (response.statusCode == 200) {
                  log('Received discover response from ${response.request.url}.');
                  ScpResponseDiscover parsedResponse =
                      ScpResponseParser.parseDiscoverResponse(
                          response, knownDevices);
                  if (parsedResponse != null) {
                    ScpDevice dev = ScpDevice(
                      deviceId: parsedResponse.deviceId,
                      deviceType: parsedResponse.deviceType,
                      deviceName: parsedResponse.deviceName,
                      currentPasswordNumber:
                          parsedResponse.currentPasswordNumber,
                      ipAddress: allIPs
                          .firstWhere((ip) => response.request.url.host == ip),
                      isDefaultPasswordSet:
                          parsedResponse.currentPasswordNumber == 0
                              ? true
                              : false,
                      knownPassword: parsedResponse.currentPasswordNumber == 0
                          ? '01234567890123456789012345678901'
                          : '',
                      controlActions: parsedResponse.controlActions,
                      measureActions: parsedResponse.measureActions,
                    );
                    log('Found device: ${dev.toJson()}');
                    if (dev.isDefaultPasswordSet) {
                      log('default password set, adding to new devices.');
                      newDevices.add(dev);
                    } else {
                      log('default password not set.');
                      bool deviceKnown = false;
                      for (ScpDevice knownDevice in knownDevices) {
                        if (knownDevice.deviceId == dev.deviceId) {
                          log('Device ${dev.deviceId} already known.');
                          deviceKnown = true;
                        }
                      }
                      if (deviceKnown == false) {
                        log('Device ${dev.deviceId} not known, adding to known devices.');
                        knownDevices.add(dev);
                      }
                    }
                  } else {
                    log('Failed parsing response.');
                  }
                }
              }
            }), onError: (e) {
      log('Could not reach device.');
    });
  }

  // Updates the IP addresses of all devices in the list of known devices
  void doUpdate(String subnet, String mask, String jsonPath) async {
    newDevices = List<ScpDevice>.empty(growable: true);
    // Get a list with all relevant IP addresses
    IPRange range = IPRange(subnet, int.parse(mask));
    List<String> allIPs = range.getAllIpAddressesInRange();

    List<Future> requests = List<Future>.empty(growable: true);

    await allIPs.forEach((ip) async {
      requests.add(ScpMessageSender.sendDiscoverHello(ip));
    });

    Future.wait(requests).then(
      (List responses) => responses.forEach((response) {
        if (response != null && response.bodyBytes != null) {
          if (response.statusCode == 200) {
            ScpResponseDiscover parsedResponse =
                ScpResponseParser.parseDiscoverResponse(response, knownDevices);
            if (parsedResponse != null) {
              // Update knowDevice from discover response
              knownDevices
                  .firstWhere(
                      (element) => element.deviceId == parsedResponse.deviceId)
                  .updateFromDiscoverResponse(parsedResponse);
              // Update IP of knownDevices from requested IPs
              knownDevices
                      .firstWhere((element) =>
                          element.deviceId == parsedResponse.deviceId)
                      .ipAddress =
                  allIPs.firstWhere((ip) => response.request.url.host == ip);
              //Store this device in JsonStorage
              JsonStorage.storeDevice(
                  knownDevices.firstWhere(
                      (element) => element.deviceId == parsedResponse.deviceId),
                  jsonPath);
              log('Updated device ${parsedResponse.deviceId}.');
            }
          }
        }
      }),
    );
  }

  void doDiscoverThenDoProvisioning(String subnet, String mask, String ssid,
      String wifiPassword, String jsonPath) async {
    newDevices = List<ScpDevice>.empty(growable: true);
    // Get a list with all relevant IP addresses
    IPRange range = IPRange(subnet, int.parse(mask));
    List<String> allIPs = range.getAllIpAddressesInRange();

    List<Future> requests = List<Future>.empty(growable: true);

    await allIPs.forEach((ip) async {
      requests.add(ScpMessageSender.sendDiscoverHello(ip));
    });

    Future.wait(requests).then(
      (List responses) => responses.forEach((response) async {
        if (response != null && response.bodyBytes != null) {
          if (response.statusCode == 200) {
            log('Received discover response.');
            ScpResponseDiscover parsedResponse =
                ScpResponseParser.parseDiscoverResponse(response, null);
            if (parsedResponse != null) {
              // create device
              ScpDevice dev = ScpDevice(
                  deviceId: parsedResponse.deviceId,
                  deviceType: parsedResponse.deviceType,
                  currentPasswordNumber: parsedResponse.currentPasswordNumber,
                  ipAddress: allIPs
                      .firstWhere((ip) => response.request.url.host == ip),
                  isDefaultPasswordSet:
                      parsedResponse.currentPasswordNumber == 0 ? true : false,
                  knownPassword: parsedResponse.currentPasswordNumber == 0
                      ? "01234567890123456789012345678901"
                      : "");
              log('Found device: ${dev.toString()}');

              if (dev.isDefaultPasswordSet) {
                log('default password set, adding to new devices.');
                newDevices.add(dev);
              } else {
                log('default password not set.');
                if (knownDevices
                    .contains((element) => element.deviceId == dev.deviceId)) {
                  log('Device ${dev.deviceId} already known.');
                } else {
                  log('Device ${dev.deviceId} not known, adding to known devices.');
                  knownDevices.add(dev);
                }
              }
              await doProvisioning(dev, ssid, wifiPassword, jsonPath);
            }
          }
        }
      }),
    );
  }

  void doProvisioning(ScpDevice device, String ssid, String wifiPassword,
      String jsonPath) async {
    if (ssid == null ||
        ssid == "" ||
        wifiPassword == null ||
        wifiPassword == "") {
      log("provisioning without ssid or wifiPassword not possible.");
      return;
    }

    // for each new device
    log('Provisioning device: ${device.deviceId}');
    // send security-pw-change
    await ScpMessageSender.sendNewPassword(device);

    // send security-wifi-config
    final wifiConfigResponse =
        await ScpMessageSender.sendWifiConfig(device, ssid, wifiPassword);
    // send security-restart
    if (wifiConfigResponse == null) {
      log('wifiConfig response is null, shutting down.');
      return;
    } else if (wifiConfigResponse == ScpStatus.RESULT_ERROR) {
      log('failed to set wifi config.');
      return;
    }
    final restartResponse = await ScpMessageSender.sendRestart(device);
    // move device from new devices to known devices
    if (restartResponse != null) {
      log('Restarting device successfull, removing from new devices and adding to known devices.');
      this.knownDevices.add(device);
      this
          .newDevices
          .removeWhere((element) => element.deviceId == device.deviceId);
      //print all device info
      log(device.toString());
      JsonStorage.storeDevice(device, jsonPath);
    }
  }

  void control(String deviceId, String command) async {
    log('do control for device: $deviceId');
    final controlResponse = await ScpMessageSender.sendControl(
        knownDevices.firstWhere((element) => element.deviceId == deviceId),
        command);
    log(controlResponse);
    if (controlResponse != null &&
        controlResponse == ScpStatus.RESULT_SUCCESS) {
      log('Successfully send control $command to $deviceId');
    } else {
      log('Failed to send control $command to $deviceId');
    }
  }

  Future<String> measure(String deviceId, String action) async {
    log('do measure for device: $deviceId');
    final ScpResponseMeasure measureResponse = await ScpMessageSender.sendMeasure(
        knownDevices.firstWhere((element) => element.deviceId == deviceId),
        action);
    log(measureResponse.toString());
    if (measureResponse != null &&
        measureResponse == ScpStatus.RESULT_SUCCESS) {
      log('Successfully send measure $action to $deviceId');
      return measureResponse.value;
    } else {
      log('Failed to send measure $action to $deviceId');
      return '';
    }
  }

  void resetToDefault(String deviceId) async {
    log('reset to default for device: $deviceId');
    final resetToDefaultResponse = await ScpMessageSender.sendResetToDefault(
        knownDevices.firstWhere((element) => element.deviceId == deviceId));
    log(resetToDefaultResponse);
    if (resetToDefaultResponse != null &&
        resetToDefaultResponse == ScpStatus.RESULT_SUCCESS) {
      log('Successfully send reset to default to $deviceId');
    } else {
      log('Failed to send reset to default to $deviceId');
    }
  }

  void rename(String deviceId, String name) async {
    log('rename for device: $deviceId');
    final renameResponse = await ScpMessageSender.sendRename(
        knownDevices.firstWhere((element) => element.deviceId == deviceId),
        name);
    log(renameResponse);
    if (renameResponse != null && renameResponse == ScpStatus.RESULT_SUCCESS) {
      log('Successfully send renamed $deviceId');
    } else {
      log('Failed to rename $deviceId');
    }
  }
}

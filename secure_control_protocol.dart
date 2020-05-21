import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:secure_control_protocol/scp.dart';

void main(List<String> args) async {
  //-d to decode and decrypt, first argument is key, second is nvcn, third is payload

  var runner = CommandRunner('dart.exe .\secure_control_protocol.dart',
      'Secure Control Protocol CLI Client');

  runner
    ..addCommand(DiscoverCommand())
    ..addCommand(ProvisionCommand())
    ..run(args).catchError((error) {
      if (error is! UsageException) throw error;
      print(runner.usage);
      exit(64); // Exit code 64 indicates a usage error.
    });
}

class DiscoverCommand extends Command {
  final name = "discover";
  final description = "Discover all devices in a given IP range.";

  DiscoverCommand() {
    argParser
      ..addOption(
        'subnet',
        abbr: 's',
        help: 'The Subnet to be scanned.',
        valueHelp: 'IPv4 Address (AAA.BBB.CCC.DDD)',
      )
      ..addOption(
        'mask',
        abbr: 'm',
        help: 'The subnet mask of the network to scan.',
        valueHelp: '0 - 32',
      );
  }

  void run() async {
    Scp scp = Scp.getInstance();
    await scp.doDiscover(argResults['subnet'], argResults['mask']);
  }
}

class ProvisionCommand extends Command {
  final name = "provision";
  final description = "Provision all available devices.";

  ProvisionCommand() {
    argParser
      ..addOption(
        'ipaddress',
        abbr: 'i',
        help: 'The Subnet to be scanned.',
        valueHelp: 'IPv4 Address (AAA.BBB.CCC.DDD)',
      )
      ..addOption(
        'mask',
        abbr: 'm',
        help: 'The subnet mask of the network to scan.',
        valueHelp: '0 - 32',
      )
      ..addOption(
        'ssid',
        abbr: 's',
        help: 'The SSID of the Wifi the device should connect to.',
        valueHelp: 'SSID',
      )
      ..addOption(
        'password',
        abbr: 'p',
        help: 'The Wifi password.',
        valueHelp: 'String (32 Characters)',
      )
      ..addFlag(
        'json',
        abbr: 'j',
        help:
            'Export the provisioned devices to JSON to be able to load them for the next command.',
      );
  }

  void run() async {
    Scp scp = Scp.getInstance();
    await scp.doDiscover(argResults['ipaddress'], argResults['mask']);
    Future.delayed(
      Duration(
        seconds: 5,
      ),
    ).then(
      (value) => scp.doProvisioning(
        argResults['ssid'],
        argResults['password'],
        argResults['json'],
      ),
    );
  }
}

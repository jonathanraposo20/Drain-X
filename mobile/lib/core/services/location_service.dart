import 'dart:async';
import 'package:geolocator/geolocator.dart';

class LocationResult {
  final double? latitude;
  final double? longitude;
  final double? accuracyMeters;
  final String? errorMessage;
  final bool isPermissionDenied;
  final bool isPermissionPermanentlyDenied;
  final bool isServiceDisabled;
  final bool isTimeout;

  const LocationResult.success({
    required this.latitude,
    required this.longitude,
    this.accuracyMeters,
  })  : errorMessage = null,
        isPermissionDenied = false,
        isPermissionPermanentlyDenied = false,
        isServiceDisabled = false,
        isTimeout = false;

  const LocationResult.failure({
    required this.errorMessage,
    this.isPermissionDenied = false,
    this.isPermissionPermanentlyDenied = false,
    this.isServiceDisabled = false,
    this.isTimeout = false,
  })  : latitude = null,
        longitude = null,
        accuracyMeters = null;

  bool get isSuccess => latitude != null && longitude != null;
}

abstract class LocationService {
  Future<LocationResult> getCurrentLocation({
    Duration timeout = const Duration(seconds: 12),
  });
  Future<bool> openAppSettings();
  Future<bool> openLocationSettings();
}

class GeolocatorLocationService implements LocationService {
  const GeolocatorLocationService();

  @override
  Future<LocationResult> getCurrentLocation({
    Duration timeout = const Duration(seconds: 12),
  }) async {
    try {
      final serviceEnabled = await Geolocator.isLocationServiceEnabled();
      if (!serviceEnabled) {
        return const LocationResult.failure(
          errorMessage: 'Device location services (GPS) are currently disabled. Please enable location services in device settings.',
          isServiceDisabled: true,
        );
      }

      var permission = await Geolocator.checkPermission();
      if (permission == LocationPermission.denied) {
        permission = await Geolocator.requestPermission();
        if (permission == LocationPermission.denied) {
          return const LocationResult.failure(
            errorMessage: 'Location permission was denied. You may enter coordinates manually or retry.',
            isPermissionDenied: true,
          );
        }
      }

      if (permission == LocationPermission.deniedForever) {
        return const LocationResult.failure(
          errorMessage: 'Location permission is permanently denied in system settings. Please enable permission in App Settings or enter coordinates manually.',
          isPermissionPermanentlyDenied: true,
        );
      }

      final position = await Geolocator.getCurrentPosition(
        locationSettings: LocationSettings(
          accuracy: LocationAccuracy.high,
          timeLimit: timeout,
        ),
      );

      return LocationResult.success(
        latitude: position.latitude,
        longitude: position.longitude,
        accuracyMeters: position.accuracy > 0 ? position.accuracy : null,
      );
    } on TimeoutException {
      return const LocationResult.failure(
        errorMessage: 'GPS acquisition timed out waiting for satellite fix. Please retry or enter coordinates manually.',
        isTimeout: true,
      );
    } catch (e) {
      return LocationResult.failure(
        errorMessage: 'Location acquisition failed: ${e.toString()}',
      );
    }
  }

  @override
  Future<bool> openAppSettings() => Geolocator.openAppSettings();

  @override
  Future<bool> openLocationSettings() => Geolocator.openLocationSettings();
}

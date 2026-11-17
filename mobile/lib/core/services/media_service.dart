import 'package:image_picker/image_picker.dart';
import '../network/api_client.dart';

abstract class MediaService {
  Future<PhotoUploadItem?> pickImageFromCamera();
  Future<PhotoUploadItem?> pickImageFromGallery();
}

class DeviceMediaService implements MediaService {
  final ImagePicker _picker;

  DeviceMediaService({ImagePicker? picker}) : _picker = picker ?? ImagePicker();

  @override
  Future<PhotoUploadItem?> pickImageFromCamera() async {
    final XFile? file = await _picker.pickImage(
      source: ImageSource.camera,
      maxWidth: 1920,
      maxHeight: 1920,
      imageQuality: 85,
    );
    if (file == null) return null;
    return _fileToUploadItem(file);
  }

  @override
  Future<PhotoUploadItem?> pickImageFromGallery() async {
    final XFile? file = await _picker.pickImage(
      source: ImageSource.gallery,
      maxWidth: 1920,
      maxHeight: 1920,
      imageQuality: 85,
    );
    if (file == null) return null;
    return _fileToUploadItem(file);
  }

  Future<PhotoUploadItem> _fileToUploadItem(XFile file) async {
    final bytes = await file.readAsBytes();
    final name = file.name.isNotEmpty ? file.name : 'evidence_${DateTime.now().millisecondsSinceEpoch}.jpg';
    final mimeType = file.mimeType ?? _inferMimeType(name);
    return PhotoUploadItem(
      filename: name,
      bytes: bytes,
      mimeType: mimeType,
    );
  }

  String _inferMimeType(String name) {
    final lower = name.toLowerCase();
    if (lower.endsWith('.png')) return 'image/png';
    if (lower.endsWith('.webp')) return 'image/webp';
    return 'image/jpeg';
  }
}

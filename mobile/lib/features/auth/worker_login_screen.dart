import 'package:flutter/material.dart';
import '../../core/auth/auth_service.dart';
import '../../models/incident.dart';
import '../../models/user_session.dart';
import '../worker/worker_dashboard_screen.dart';

class WorkerLoginScreen extends StatefulWidget {
  const WorkerLoginScreen({super.key});

  @override
  State<WorkerLoginScreen> createState() => _WorkerLoginScreenState();
}

class _WorkerLoginScreenState extends State<WorkerLoginScreen> {
  final List<Map<String, String>> _demoWorkers = [
    {
      'name': 'R. Shirodkar (Crew Lead)',
      'team': IncidentConstants.fieldTeams[0], // Team Alpha — St. Inez Drainage Crew
    },
    {
      'name': 'A. Gaonkar (Field Technician)',
      'team': IncidentConstants.fieldTeams[1], // Team Beta — Patto Rapid Response
    },
    {
      'name': 'S. Naik (Maintenance Operator)',
      'team': IncidentConstants.fieldTeams[2], // Team Gamma — Fontainhas Heritage Maintenance
    },
    {
      'name': 'V. Kamat (Sluice & Outfall Specialist)',
      'team': IncidentConstants.fieldTeams[3], // Team Delta — Miramar Outfall Sluice Unit
    },
  ];

  late String _selectedWorkerName;
  late String _selectedTeam;

  @override
  void initState() {
    super.initState();
    _selectedWorkerName = _demoWorkers[0]['name']!;
    _selectedTeam = _demoWorkers[0]['team']!;
  }

  void _proceedToWorkerDashboard() {
    AuthService().loginDemo(
      role: UserRole.fieldWorker,
      displayName: _selectedWorkerName,
      assignedTeam: _selectedTeam,
    );

    Navigator.pushReplacement(
      context,
      MaterialPageRoute(
        builder: (_) => WorkerDashboardScreen(
          workerName: _selectedWorkerName,
          assignedTeam: _selectedTeam,
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Field Worker Demo Login'),
        backgroundColor: const Color(0xFF0F172A),
      ),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(20),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Header Icon and Title
              Row(
                children: [
                  Container(
                    padding: const EdgeInsets.all(10),
                    decoration: BoxDecoration(
                      color: const Color(0xFFFEF3C7),
                      borderRadius: BorderRadius.circular(10),
                    ),
                    child: const Icon(Icons.handyman_outlined, size: 28, color: Color(0xFFD97706)),
                  ),
                  const SizedBox(width: 12),
                  const Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'Field Maintenance Crew Console',
                          style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold, color: Color(0xFF0F172A)),
                        ),
                        Text(
                          'On-ground Drainage Triage & Evidence Dispatch',
                          style: TextStyle(fontSize: 12, color: Color(0xFF64748B)),
                        ),
                      ],
                    ),
                  ),
                ],
              ),

              const SizedBox(height: 20),

              // Demo Notice Banner
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: const Color(0xFFFFFBEB),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: const Color(0xFFFDE68A)),
                ),
                child: const Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Icon(Icons.construction, size: 16, color: Color(0xFFD97706)),
                    SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        'DEMO MODE: Password authentication is disabled for evaluation. Selecting a field crew identity associates investigation logs, status transitions, and photo evidence with that unit.',
                        style: TextStyle(fontSize: 11, color: Color(0xFF92400E), height: 1.4),
                      ),
                    ),
                  ],
                ),
              ),

              const SizedBox(height: 24),

              const Text(
                'FIELD CREW / TECHNICIAN IDENTITY',
                style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Color(0xFF475569), letterSpacing: 0.5),
              ),
              const SizedBox(height: 8),

              RadioGroup<String>(
                groupValue: _selectedWorkerName,
                onChanged: (val) {
                  if (val != null) {
                    final match = _demoWorkers.firstWhere((w) => w['name'] == val);
                    setState(() {
                      _selectedWorkerName = val;
                      _selectedTeam = match['team']!;
                    });
                  }
                },
                child: Column(
                  children: _demoWorkers.map((worker) {
                    final name = worker['name']!;
                    final team = worker['team']!;
                    final isSelected = _selectedWorkerName == name;

                    return Padding(
                      padding: const EdgeInsets.only(bottom: 10),
                      child: Material(
                        color: isSelected ? const Color(0xFFFFFBEB) : Colors.white,
                        shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(10),
                          side: BorderSide(
                            color: isSelected ? const Color(0xFFF59E0B) : const Color(0xFFE2E8F0),
                            width: isSelected ? 1.5 : 1,
                          ),
                        ),
                        child: RadioListTile<String>(
                          title: Text(
                            name,
                            style: TextStyle(
                              fontSize: 13,
                              fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
                              color: const Color(0xFF0F172A),
                            ),
                          ),
                          subtitle: Text(
                            team,
                            style: const TextStyle(fontSize: 11, color: Color(0xFF64748B)),
                          ),
                          value: name,
                          activeColor: const Color(0xFFD97706),
                        ),
                      ),
                    );
                  }).toList(),
                ),
              ),

              const SizedBox(height: 32),

              // Action Button
              SizedBox(
                width: double.infinity,
                child: ElevatedButton.icon(
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFFD97706),
                    padding: const EdgeInsets.symmetric(vertical: 14),
                  ),
                  onPressed: _proceedToWorkerDashboard,
                  icon: const Icon(Icons.assignment_turned_in_outlined, color: Colors.white),
                  label: const Text(
                    'ENTER WORKER CONSOLE',
                    style: TextStyle(fontWeight: FontWeight.bold, letterSpacing: 0.5, color: Colors.white),
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

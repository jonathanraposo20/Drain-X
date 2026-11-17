import 'package:flutter/material.dart';
import '../../app/routes.dart';
import '../../core/auth/auth_service.dart';
import '../../core/network/api_client.dart';
import '../../models/incident.dart';
import '../../widgets/empty_state_view.dart';
import '../../widgets/incident_card.dart';
import '../../widgets/kpi_card.dart';
import '../municipal/municipal_incident_detail_screen.dart';

class WorkerDashboardScreen extends StatefulWidget {
  final String workerName;
  final String assignedTeam;

  const WorkerDashboardScreen({
    super.key,
    required this.workerName,
    required this.assignedTeam,
  });

  @override
  State<WorkerDashboardScreen> createState() => _WorkerDashboardScreenState();
}

class _WorkerDashboardScreenState extends State<WorkerDashboardScreen> {
  final ApiClient _apiClient = ApiClient();
  List<Incident> _incidents = [];
  bool _isLoading = true;
  String? _errorMessage;
  String _selectedFilter = 'MY_CREW'; // 'MY_CREW' or 'ALL_ACTIVE'

  @override
  void initState() {
    super.initState();
    _fetchIncidents();
  }

  Future<void> _fetchIncidents() async {
    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });

    try {
      final incidents = await _apiClient.getIncidents();
      setState(() {
        _incidents = incidents;
        _isLoading = false;
      });
    } catch (e) {
      setState(() {
        _errorMessage = e.toString();
        _isLoading = false;
      });
    }
  }

  void _confirmLogout() {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Confirm Worker Logout'),
        content: const Text('Are you sure you want to end your field crew session?'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFFDC2626)),
            onPressed: () {
              Navigator.pop(ctx);
              AuthService().logout();
              Navigator.pushNamedAndRemoveUntil(context, AppRoutes.welcome, (route) => false);
            },
            child: const Text('Logout', style: TextStyle(color: Colors.white)),
          ),
        ],
      ),
    );
  }

  List<Incident> get _filteredIncidents {
    if (_selectedFilter == 'MY_CREW') {
      return _incidents.where((i) => i.assignedTo == widget.assignedTeam).toList();
    }
    // All active un-resolved tickets
    return _incidents.where((i) => i.status != 'RESOLVED' && i.status != 'REJECTED').toList();
  }

  @override
  Widget build(BuildContext context) {
    final myCrewCount = _incidents.where((i) => i.assignedTo == widget.assignedTeam).length;
    final inProgressCount = _incidents
        .where((i) => i.assignedTo == widget.assignedTeam && i.status == 'INVESTIGATING')
        .length;
    final resolvedCount = _incidents
        .where((i) => i.assignedTo == widget.assignedTeam && i.status == 'RESOLVED')
        .length;

    return Scaffold(
      backgroundColor: const Color(0xFFF8FAFC),
      appBar: AppBar(
        title: const Text('Worker Field Console'),
        backgroundColor: const Color(0xFF0F172A),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            tooltip: 'Refresh tasks',
            onPressed: _fetchIncidents,
          ),
          IconButton(
            icon: const Icon(Icons.logout),
            tooltip: 'Sign Out',
            onPressed: _confirmLogout,
          ),
        ],
      ),
      body: SafeArea(
        child: RefreshIndicator(
          onRefresh: _fetchIncidents,
          child: CustomScrollView(
            slivers: [
              // Top Banner with Worker Badge and Crew
              SliverToBoxAdapter(
                child: Container(
                  padding: const EdgeInsets.all(16),
                  color: const Color(0xFF0F172A),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Container(
                            padding: const EdgeInsets.all(8),
                            decoration: BoxDecoration(
                              color: const Color(0xFFD97706),
                              borderRadius: BorderRadius.circular(8),
                            ),
                            child: const Icon(Icons.engineering, size: 22, color: Colors.white),
                          ),
                          const SizedBox(width: 12),
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  widget.workerName,
                                  style: const TextStyle(
                                    fontSize: 15,
                                    fontWeight: FontWeight.bold,
                                    color: Colors.white,
                                  ),
                                ),
                                const SizedBox(height: 2),
                                Text(
                                  widget.assignedTeam,
                                  style: const TextStyle(
                                    fontSize: 12,
                                    color: Color(0xFFFBBF24),
                                    fontWeight: FontWeight.w500,
                                  ),
                                ),
                              ],
                            ),
                          ),
                          Container(
                            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                            decoration: BoxDecoration(
                              color: const Color(0xFF1E293B),
                              borderRadius: BorderRadius.circular(6),
                              border: Border.all(color: const Color(0xFFF59E0B)),
                            ),
                            child: const Text(
                              'FIELD CREW',
                              style: TextStyle(
                                fontSize: 10,
                                fontWeight: FontWeight.bold,
                                color: Color(0xFFF59E0B),
                                letterSpacing: 0.5,
                              ),
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
              ),

              // KPI Summary Cards
              SliverToBoxAdapter(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Row(
                    children: [
                      Expanded(
                        child: KpiCard(
                          title: 'My Tasks',
                          value: myCrewCount.toString(),
                          icon: Icons.assignment_outlined,
                          accentColor: const Color(0xFFD97706),
                        ),
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: KpiCard(
                          title: 'Investigating',
                          value: inProgressCount.toString(),
                          icon: Icons.search,
                          accentColor: const Color(0xFFF59E0B),
                        ),
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: KpiCard(
                          title: 'Resolved',
                          value: resolvedCount.toString(),
                          icon: Icons.check_circle_outline,
                          accentColor: const Color(0xFF10B981),
                        ),
                      ),
                    ],
                  ),
                ),
              ),

              // Filter Tabs (My Crew Tasks vs All Active Incidents)
              SliverToBoxAdapter(
                child: Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 16),
                  child: Row(
                    children: [
                      Expanded(
                        child: ElevatedButton(
                          style: ElevatedButton.styleFrom(
                            backgroundColor: _selectedFilter == 'MY_CREW'
                                ? const Color(0xFFD97706)
                                : const Color(0xFFE2E8F0),
                            foregroundColor: _selectedFilter == 'MY_CREW'
                                ? Colors.white
                                : const Color(0xFF334155),
                            elevation: _selectedFilter == 'MY_CREW' ? 2 : 0,
                          ),
                          onPressed: () => setState(() => _selectedFilter = 'MY_CREW'),
                          child: Text('MY CREW ($myCrewCount)'),
                        ),
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: ElevatedButton(
                          style: ElevatedButton.styleFrom(
                            backgroundColor: _selectedFilter == 'ALL_ACTIVE'
                                ? const Color(0xFFD97706)
                                : const Color(0xFFE2E8F0),
                            foregroundColor: _selectedFilter == 'ALL_ACTIVE'
                                ? Colors.white
                                : const Color(0xFF334155),
                            elevation: _selectedFilter == 'ALL_ACTIVE' ? 2 : 0,
                          ),
                          onPressed: () => setState(() => _selectedFilter = 'ALL_ACTIVE'),
                          child: const Text('ALL ACTIVE'),
                        ),
                      ),
                    ],
                  ),
                ),
              ),

              const SliverToBoxAdapter(child: SizedBox(height: 12)),

              // Content Area: Loading / Error / Empty / List
              if (_isLoading)
                const SliverFillRemaining(
                  child: Center(
                    child: CircularProgressIndicator(color: Color(0xFFD97706)),
                  ),
                )
              else if (_errorMessage != null)
                SliverFillRemaining(
                  child: Center(
                    child: Padding(
                      padding: const EdgeInsets.all(24),
                      child: Column(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          const Icon(Icons.cloud_off, size: 48, color: Color(0xFF94A3B8)),
                          const SizedBox(height: 12),
                          Text(
                            _errorMessage!,
                            textAlign: TextAlign.center,
                            style: const TextStyle(fontSize: 13, color: Color(0xFF64748B)),
                          ),
                          const SizedBox(height: 16),
                          ElevatedButton(
                            onPressed: _fetchIncidents,
                            child: const Text('Retry Connection'),
                          ),
                        ],
                      ),
                    ),
                  ),
                )
              else if (_filteredIncidents.isEmpty)
                SliverFillRemaining(
                  child: EmptyStateView(
                    icon: Icons.task_alt,
                    title: _selectedFilter == 'MY_CREW'
                        ? 'No Tasks Assigned Yet'
                        : 'No Active Drainage Incidents',
                    description: _selectedFilter == 'MY_CREW'
                        ? 'Your crew (${widget.assignedTeam}) has no pending tasks assigned at this moment.'
                        : 'All reported drainage incidents have been resolved.',
                  ),
                )
              else
                SliverList(
                  delegate: SliverChildBuilderDelegate(
                    (context, index) {
                      final incident = _filteredIncidents[index];
                      return IncidentCard(
                        incident: incident,
                        onTap: () async {
                          await Navigator.push(
                            context,
                            MaterialPageRoute(
                              builder: (_) => MunicipalIncidentDetailScreen(
                                incidentId: incident.id,
                                officerName: widget.workerName,
                              ),
                            ),
                          );
                          _fetchIncidents();
                        },
                      );
                    },
                    childCount: _filteredIncidents.length,
                  ),
                ),

              const SliverToBoxAdapter(child: SizedBox(height: 24)),
            ],
          ),
        ),
      ),
    );
  }
}

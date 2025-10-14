"""Data Export and Reporting Module"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional
from enum import Enum
import json
import csv
import io

class ReportType(Enum):
    EXPERIMENT_SUMMARY = "experiment_summary"
    LAB_USAGE = "lab_usage"
    INVENTORY_STATUS = "inventory_status"
    SAFETY_AUDIT = "safety_audit"
    MAINTENANCE_REPORT = "maintenance_report"
    RESEARCH_OUTPUT = "research_output"

class ExportFormat(Enum):
    JSON = "json"
    CSV = "csv"
    PDF = "pdf"
    EXCEL = "excel"

@dataclass
class Report:
    id: str = ""
    report_type: ReportType = ReportType.EXPERIMENT_SUMMARY
    title: str = ""
    generated_by: str = ""
    generated_at: datetime = field(default_factory=datetime.utcnow)
    data: Dict = field(default_factory=dict)
    filters: Dict = field(default_factory=dict)
    summary: Dict = field(default_factory=dict)

class ReportingSystem:
    def __init__(self, lab_manager, experiment_tracker, inventory_system, 
                 safety_system, maintenance_system):
        self.lab_manager = lab_manager
        self.experiment_tracker = experiment_tracker
        self.inventory_system = inventory_system
        self.safety_system = safety_system
        self.maintenance_system = maintenance_system
        self.reports: Dict[str, Report] = {}
    
    def generate_experiment_summary(self, start_date: datetime, 
                                    end_date: datetime, lab_id: Optional[str] = None) -> Report:
        experiments = [e for e in self.experiment_tracker.experiments.values()
                      if start_date <= e.created_at <= end_date]
        
        if lab_id:
            experiments = [e for e in experiments if e.lab_id == lab_id]
        
        completed = len([e for e in experiments if e.status.value == "completed"])
        running = len([e for e in experiments if e.status.value == "running"])
        
        report = Report(
            id=f"exp_summary_{datetime.utcnow().isoformat()}",
            report_type=ReportType.EXPERIMENT_SUMMARY,
            title="Experiment Summary Report",
            data={"experiments": [self._experiment_to_dict(e) for e in experiments]},
            summary={
                "total_experiments": len(experiments),
                "completed": completed,
                "running": running,
                "success_rate": completed / len(experiments) if experiments else 0
            }
        )
        self.reports[report.id] = report
        return report
    
    def generate_lab_usage_report(self, start_date: datetime, 
                                  end_date: datetime) -> Report:
        bookings = [b for b in self.lab_manager.bookings.values()
                   if start_date <= b.start_time <= end_date]
        
        usage_by_lab = {}
        for booking in bookings:
            if booking.resource_type.value == "equipment":
                eq = self.lab_manager.equipment.get(booking.resource_id)
                if eq:
                    lab_id = eq.lab_id
                    usage_by_lab[lab_id] = usage_by_lab.get(lab_id, 0) + 1
        
        report = Report(
            id=f"lab_usage_{datetime.utcnow().isoformat()}",
            report_type=ReportType.LAB_USAGE,
            title="Lab Usage Report",
            data={"bookings": [self._booking_to_dict(b) for b in bookings]},
            summary={
                "total_bookings": len(bookings),
                "usage_by_lab": usage_by_lab,
                "average_booking_hours": sum(
                    (b.end_time - b.start_time).total_seconds() / 3600 
                    for b in bookings
                ) / len(bookings) if bookings else 0
            }
        )
        self.reports[report.id] = report
        return report
    
    def generate_inventory_status_report(self) -> Report:
        all_items = list(self.inventory_system.items.values())
        low_stock = self.inventory_system.check_low_stock()
        expiring = self.inventory_system.check_expiring_items(30)
        
        total_value = sum(item.quantity * 10 for item in all_items)  # Simplified
        
        report = Report(
            id=f"inventory_{datetime.utcnow().isoformat()}",
            report_type=ReportType.INVENTORY_STATUS,
            title="Inventory Status Report",
            data={"items": [self._inventory_item_to_dict(i) for i in all_items]},
            summary={
                "total_items": len(all_items),
                "low_stock_count": len(low_stock),
                "expiring_soon_count": len(expiring),
                "estimated_total_value": total_value
            }
        )
        self.reports[report.id] = report
        return report
    
    def generate_safety_audit_report(self, start_date: datetime, 
                                     end_date: datetime) -> Report:
        incidents = [i for i in self.safety_system.incidents.values()
                    if start_date <= i.timestamp <= end_date]
        
        open_incidents = [i for i in incidents if not i.resolved]
        critical = [i for i in incidents if i.hazard_level.value == "critical"]
        
        report = Report(
            id=f"safety_{datetime.utcnow().isoformat()}",
            report_type=ReportType.SAFETY_AUDIT,
            title="Safety Audit Report",
            data={"incidents": [self._incident_to_dict(i) for i in incidents]},
            summary={
                "total_incidents": len(incidents),
                "open_incidents": len(open_incidents),
                "critical_incidents": len(critical),
                "average_resolution_time_hours": self._calculate_avg_resolution(incidents)
            }
        )
        self.reports[report.id] = report
        return report
    
    def generate_maintenance_report(self, start_date: datetime, 
                                    end_date: datetime) -> Report:
        maintenance = [m for m in self.maintenance_system.maintenance_records.values()
                      if start_date <= m.scheduled_date <= end_date]
        
        completed = [m for m in maintenance if m.status.value == "completed"]
        total_cost = sum(m.cost for m in completed)
        
        report = Report(
            id=f"maintenance_{datetime.utcnow().isoformat()}",
            report_type=ReportType.MAINTENANCE_REPORT,
            title="Maintenance Report",
            data={"maintenance": [self._maintenance_to_dict(m) for m in maintenance]},
            summary={
                "total_maintenance": len(maintenance),
                "completed": len(completed),
                "total_cost": total_cost,
                "average_cost": total_cost / len(completed) if completed else 0
            }
        )
        self.reports[report.id] = report
        return report
    
    def export_report(self, report_id: str, format: ExportFormat) -> str:
        if report_id not in self.reports:
            raise ValueError("Report not found")
        
        report = self.reports[report_id]
        
        if format == ExportFormat.JSON:
            return self._export_json(report)
        elif format == ExportFormat.CSV:
            return self._export_csv(report)
        else:
            raise NotImplementedError(f"Export format {format} not implemented")
    
    def _export_json(self, report: Report) -> str:
        return json.dumps({
            "id": report.id,
            "type": report.report_type.value,
            "title": report.title,
            "generated_at": report.generated_at.isoformat(),
            "summary": report.summary,
            "data": report.data
        }, indent=2)
    
    def _export_csv(self, report: Report) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(["Report", report.title])
        writer.writerow(["Generated", report.generated_at.isoformat()])
        writer.writerow([])
        
        # Write summary
        writer.writerow(["Summary"])
        for key, value in report.summary.items():
            writer.writerow([key, value])
        writer.writerow([])
        
        # Write data
        if report.data:
            first_key = list(report.data.keys())[0]
            if isinstance(report.data[first_key], list) and report.data[first_key]:
                # Assume list of dicts
                items = report.data[first_key]
                if items:
                    headers = list(items[0].keys())
                    writer.writerow(headers)
                    for item in items:
                        writer.writerow([item.get(h, "") for h in headers])
        
        return output.getvalue()
    
    def _experiment_to_dict(self, exp) -> Dict:
        return {
            "id": exp.id,
            "title": exp.title,
            "status": exp.status.value,
            "researcher": exp.researcher_id,
            "created_at": exp.created_at.isoformat()
        }
    
    def _booking_to_dict(self, booking) -> Dict:
        return {
            "id": booking.id,
            "resource_id": booking.resource_id,
            "user": booking.user_id,
            "start": booking.start_time.isoformat(),
            "end": booking.end_time.isoformat()
        }
    
    def _inventory_item_to_dict(self, item) -> Dict:
        return {
            "id": item.id,
            "name": item.name,
            "quantity": item.quantity,
            "unit": item.unit
        }
    
    def _incident_to_dict(self, incident) -> Dict:
        return {
            "id": incident.id,
            "type": incident.incident_type.value,
            "hazard_level": incident.hazard_level.value,
            "timestamp": incident.timestamp.isoformat(),
            "resolved": incident.resolved
        }
    
    def _maintenance_to_dict(self, maintenance) -> Dict:
        return {
            "id": maintenance.id,
            "equipment_id": maintenance.equipment_id,
            "type": maintenance.maintenance_type.value,
            "status": maintenance.status.value,
            "cost": maintenance.cost
        }
    
    def _calculate_avg_resolution(self, incidents: List) -> float:
        resolved = [i for i in incidents if i.resolved and i.resolution_time]
        if not resolved:
            return 0.0
        total_hours = sum(
            (i.resolution_time - i.timestamp).total_seconds() / 3600 
            for i in resolved
        )
        return total_hours / len(resolved)

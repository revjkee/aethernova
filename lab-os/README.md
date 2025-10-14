# Lab OS - Laboratory Management System

**Comprehensive laboratory management platform for scientific research facilities**

## 🔬 Overview

Lab OS is a complete laboratory management system designed for research institutions, universities, and R&D facilities. It provides comprehensive tools for managing labs, equipment, experiments, resources, collaboration, and inventory.

### Key Features

- **Lab & Equipment Management**: Centralized management of laboratories, equipment, and bookings
- **Experiment Tracking**: Protocol versioning, experiment tracking, reproducibility verification
- **Resource Allocation**: Intelligent priority-based resource allocation with conflict resolution
- **Team Collaboration**: Shared experiments, team management, notifications
- **Data Analysis**: Statistical analysis, correlation detection, automated reporting
- **Inventory Management**: Chemical tracking, expiration alerts, automatic reordering
- **REST API**: 30+ endpoints with full CRUD operations
- **Real-time Updates**: WebSocket support for live notifications

## 📦 Installation

### Requirements

- Python 3.10+
- PostgreSQL 13+
- Redis 6+

### Quick Start

```bash
# Clone repository
git clone <repository-url>
cd lab-os

# Install dependencies
pip install -r requirements.txt

# Configure database
export DATABASE_URL="postgresql://user:password@localhost/labos"
export REDIS_URL="redis://localhost:6379"

# Run migrations
alembic upgrade head

# Start server
uvicorn api:app --reload --host 0.0.0.0 --port 8000
```

## 🏗️ Architecture

### Core Modules

1. **Lab Manager** (`lab_manager.py`)
   - Lab creation and management
   - Equipment tracking and maintenance
   - Booking system with conflict detection
   - Access control and permissions

2. **Experiment Tracker** (`experiment_tracker.py`)
   - Protocol versioning and management
   - Experiment lifecycle tracking
   - Observation and result recording
   - Reproducibility verification
   - Experiment cloning

3. **Resource Allocator** (`resource_allocator.py`)
   - Priority-based allocation
   - Conflict resolution
   - Queue management
   - Resource optimization

4. **Collaboration Hub** (`collaboration_hub.py`)
   - Team management
   - Shared experiments
   - Notifications and updates
   - Comment system

5. **Analysis Engine** (`analysis_engine.py`)
   - Statistical analysis (mean, std, variance)
   - Correlation detection
   - Pattern recognition
   - Automated reporting

6. **Inventory System** (`inventory_system.py`)
   - Chemical and material tracking
   - Expiration monitoring
   - Low stock alerts
   - Automatic reordering

## 🚀 API Reference

### Labs

#### Create Lab
```http
POST /api/v1/labs
Content-Type: application/json

{
  "name": "Biochemistry Lab",
  "location": "Building A, Floor 3",
  "capacity": 20,
  "manager_id": "user123"
}
```

#### Get All Labs
```http
GET /api/v1/labs
```

#### Update Lab Status
```http
PUT /api/v1/labs/{lab_id}/status
Content-Type: application/json

{
  "status": "active"
}
```

### Equipment

#### Add Equipment
```http
POST /api/v1/equipment
Content-Type: application/json

{
  "lab_id": "lab123",
  "name": "Microscope XYZ",
  "equipment_type": "optical_microscope"
}
```

#### Get Equipment by Lab
```http
GET /api/v1/labs/{lab_id}/equipment
```

### Bookings

#### Create Booking
```http
POST /api/v1/bookings
Content-Type: application/json

{
  "resource_id": "eq123",
  "resource_type": "equipment",
  "user_id": "user456",
  "start_time": "2024-01-15T10:00:00Z",
  "end_time": "2024-01-15T12:00:00Z",
  "purpose": "Sample analysis"
}
```

#### Get User Bookings
```http
GET /api/v1/bookings/user/{user_id}
```

### Protocols

#### Create Protocol
```http
POST /api/v1/protocols
Content-Type: application/json

{
  "name": "PCR Protocol",
  "description": "Standard PCR procedure",
  "steps": [
    {"step": 1, "action": "Prepare samples", "duration": 30},
    {"step": 2, "action": "Mix reagents", "duration": 15}
  ],
  "created_by": "researcher1"
}
```

### Experiments

#### Create Experiment
```http
POST /api/v1/experiments
Content-Type: application/json

{
  "title": "Gene Expression Study",
  "protocol_id": "proto123",
  "researcher_id": "researcher1",
  "lab_id": "lab123",
  "objectives": ["Measure expression levels", "Compare treatments"]
}
```

#### Add Observation
```http
POST /api/v1/experiments/{experiment_id}/observations
Content-Type: application/json

{
  "text": "Initial observations look promising",
  "metadata": {"temperature": 25.0, "ph": 7.4}
}
```

#### Update Status
```http
PUT /api/v1/experiments/{experiment_id}/status
Content-Type: application/json

{
  "status": "running"
}
```

#### Clone Experiment
```http
POST /api/v1/experiments/{experiment_id}/clone
Content-Type: application/json

{
  "new_title": "Replicate Experiment",
  "researcher_id": "researcher2"
}
```

### Analysis

#### Analyze Experiment
```http
POST /api/v1/analysis/experiments/{experiment_id}
Content-Type: application/json

{
  "data": {
    "temperature": [20.0, 21.0, 22.0],
    "pressure": [1.0, 1.1, 1.2]
  },
  "analyses": ["basic_stats", "correlation"]
}
```

#### Get Analysis Results
```http
GET /api/v1/analysis/experiments/{experiment_id}/results
```

### Inventory

#### Add Inventory Item
```http
POST /api/v1/inventory
Content-Type: application/json

{
  "name": "Sodium Chloride",
  "category": "chemicals",
  "quantity": 500.0,
  "unit": "g",
  "location": "Storage A-12",
  "reorder_level": 100.0,
  "expiration_date": "2025-12-31T23:59:59Z"
}
```

#### Update Quantity
```http
PUT /api/v1/inventory/{item_id}/quantity
Content-Type: application/json

{
  "delta": -50.0,
  "reason": "Used in Experiment X"
}
```

#### Check Low Stock
```http
GET /api/v1/inventory/low-stock
```

#### Check Expiring Items
```http
GET /api/v1/inventory/expiring?days=30
```

### Teams

#### Create Team
```http
POST /api/v1/teams
Content-Type: application/json

{
  "name": "Molecular Biology Team",
  "creator_id": "user123"
}
```

#### Add Member
```http
POST /api/v1/teams/{team_id}/members
Content-Type: application/json

{
  "user_id": "user456"
}
```

#### Share Experiment
```http
POST /api/v1/teams/{team_id}/experiments
Content-Type: application/json

{
  "experiment_id": "exp123"
}
```

### WebSocket

#### Real-time Updates
```javascript
const ws = new WebSocket("ws://localhost:8000/ws/{client_id}");

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log("Update:", data);
};

// Receive notifications for:
// - New bookings
// - Experiment status changes
// - Low stock alerts
// - Expiring items
// - Team updates
```

## 🔧 Configuration

### Environment Variables

```bash
# Database
DATABASE_URL=postgresql://user:password@localhost/labos
DATABASE_POOL_SIZE=10
DATABASE_MAX_OVERFLOW=20

# Redis
REDIS_URL=redis://localhost:6379
REDIS_MAX_CONNECTIONS=50

# API
API_HOST=0.0.0.0
API_PORT=8000
API_WORKERS=4
API_RELOAD=false

# Security
SECRET_KEY=your-secret-key-here
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

# Integrations
IDENTITY_SERVICE_URL=http://identity-service:8001
AUDIT_SERVICE_URL=http://audit-service:8002
```

### Database Schema

```sql
-- Labs
CREATE TABLE labs (
  id UUID PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  location VARCHAR(500),
  capacity INT,
  status VARCHAR(50),
  manager_id VARCHAR(255),
  created_at TIMESTAMP DEFAULT NOW()
);

-- Equipment
CREATE TABLE equipment (
  id UUID PRIMARY KEY,
  lab_id UUID REFERENCES labs(id),
  name VARCHAR(255) NOT NULL,
  equipment_type VARCHAR(100),
  status VARCHAR(50),
  created_at TIMESTAMP DEFAULT NOW()
);

-- Bookings
CREATE TABLE bookings (
  id UUID PRIMARY KEY,
  resource_id UUID NOT NULL,
  resource_type VARCHAR(50),
  user_id VARCHAR(255),
  start_time TIMESTAMP,
  end_time TIMESTAMP,
  purpose TEXT,
  status VARCHAR(50),
  created_at TIMESTAMP DEFAULT NOW()
);

-- Protocols
CREATE TABLE protocols (
  id UUID PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  steps JSONB,
  version INT,
  created_by VARCHAR(255),
  created_at TIMESTAMP DEFAULT NOW()
);

-- Experiments
CREATE TABLE experiments (
  id UUID PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  protocol_id UUID REFERENCES protocols(id),
  researcher_id VARCHAR(255),
  lab_id UUID REFERENCES labs(id),
  status VARCHAR(50),
  objectives JSONB,
  observations JSONB,
  results JSONB,
  parent_experiment_id UUID,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Inventory
CREATE TABLE inventory (
  id UUID PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  category VARCHAR(100),
  quantity DECIMAL(10,2),
  unit VARCHAR(50),
  location VARCHAR(255),
  reorder_level DECIMAL(10,2),
  expiration_date TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW()
);
```

## 📊 Usage Examples

### Complete Experiment Workflow

```python
from lab_manager import LabManager, ResourceType
from experiment_tracker import ExperimentTracker
from analysis_engine import AnalysisEngine

# 1. Setup lab and equipment
lab_manager = LabManager()
lab = lab_manager.create_lab("Lab A", "Building 1", 15, "manager1")
microscope = lab_manager.add_equipment(lab.id, "Microscope", "optical")

# 2. Create booking
booking = lab_manager.create_booking(
    microscope.id, ResourceType.EQUIPMENT, "researcher1",
    start_time, end_time, "Cell imaging"
)

# 3. Create protocol and experiment
tracker = ExperimentTracker()
protocol = tracker.create_protocol(
    "Cell Staining", "Standard protocol",
    [{"step": 1, "action": "Prepare slides"}], "researcher1"
)
experiment = tracker.create_experiment(
    "Cell Study A", protocol.id, "researcher1", lab.id
)

# 4. Run experiment
tracker.update_experiment_status(experiment.id, "running")
tracker.add_observation(experiment.id, "Cells look healthy")
tracker.add_result(experiment.id, "count", {"cells": 1500})

# 5. Analyze results
engine = AnalysisEngine()
data = {"cell_count": [1500, 1450, 1520, 1480]}
analysis = engine.analyze_experiment(experiment.id, data)

# 6. Complete experiment
tracker.update_experiment_status(experiment.id, "completed")
```

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test module
pytest tests/test_lab_os.py -v

# Run with coverage
pytest tests/ --cov=. --cov-report=html

# Run integration tests
pytest tests/ -m integration
```

## 🔐 Security

- JWT-based authentication
- Role-based access control (RBAC)
- Audit trail for all operations
- Encryption at rest and in transit
- Rate limiting and DDoS protection

## 📈 Performance

- **Request throughput**: 1000+ req/s
- **Concurrent users**: 500+
- **Database connections**: Pooled (10-30)
- **Response time**: <100ms (p95)
- **WebSocket connections**: 1000+

## 🐛 Troubleshooting

### Database Connection Issues
```bash
# Check PostgreSQL status
systemctl status postgresql

# Test connection
psql -h localhost -U labos -d labos
```

### Redis Connection Issues
```bash
# Check Redis status
redis-cli ping

# Monitor Redis
redis-cli monitor
```

## 📝 License

MIT License - See LICENSE file for details

## 👥 Contributing

Contributions welcome! Please read CONTRIBUTING.md first.

## 📞 Support

- Documentation: https://docs.labos.io
- Issues: https://github.com/aethernova/lab-os/issues
- Email: support@labos.io

---

**Lab OS** - Modern laboratory management for the 21st century 🔬

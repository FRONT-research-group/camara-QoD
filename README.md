# CAMARA Quality on Demand (QoD) API and AsSessionWithQoS NEF - Docker Compose

This repository contains a Docker Compose setup to run both the **CAMARA QoD API** and **NEF AsSessionWithQoS** services together.

## Overview

This deployment consists of two interconnected services:

1. **NEF-QoS Service** (`nef-qos`): Implements the 3GPP AsSessionWithQoS API for network exposure functions
2. **CAMARA QoD Service** (`camara-qod`): Implements the CAMARA Quality on Demand API specification

The CAMARA QoD service acts as a northbound interface translating CAMARA-compliant requests to 3GPP AsSessionWithQoS calls.

## Architecture

```
┌─────────────────┐
│  Application    │
│  (Your Code)    │
└────────┬────────┘
         │ CAMARA QoD API
         │ (Port 8584)
         ▼
┌─────────────────┐
│  camara-qod     │
│  Container      │
└────────┬────────┘
         │ AsSessionWithQoS API
         │ (Internal: nef-qos:8001)
         ▼
┌─────────────────┐
│  nef-qos        │
│  Container      │
└────────┬────────┘
         │ HTTP/2
         │ (To PCF)
         ▼
┌─────────────────┐
│  5G Core PCF    │
└─────────────────┘
```

## Services

### NEF-QoS Service

- **Image**: `ghcr.io/front-research-group/nef-qos:latest`
- **Port**: `8585:8001`
- **API Base**: `http://localhost:8585/3gpp-as-session-with-qos/v1`

Implements 3GPP TS 29.122 Application Session Context with QoS API.

**Environment Variables**:
- `PCF_BASE_URL`: IP address of the Policy Control Function (default: `10.220.2.73`)
- `PCF_PORT`: PCF port (default: `8086`)
- `QOS_MAPPING`: JSON mapping of QoS profiles to network parameters

**QoS Profiles**:
- `QOS_E`: 5 Mbps DL / 5 Mbps UL max, 2 Mbps DL / 2 Mbps UL min (Video)
- `QOS_L`: 35 Mbps DL / 18 Mbps UL max, 25 Mbps DL / 15 Mbps UL min (Video)
- `QOS_M`: 20 Mbps DL / 10 Mbps UL max, 15 Mbps DL / 5 Mbps UL min (Video)
- `QOS_S`: 15 Mbps DL / 10 Mbps UL max, 10 Mbps DL / 5 Mbps UL min (Video)

### CAMARA QoD Service

- **Image**: `ghcr.io/front-research-group/camara-qod:latest`
- **Port**: `8584:8002`
- **API Base**: `http://localhost:8584/qod/v0`

Implements CAMARA Quality-on-Demand API specification.

**Environment Variables**:
- `ASSESSIONWITHQOS_URL`: Internal URL to NEF-QoS service (default: `http://nef-qos:8001/3gpp-as-session-with-qos/v1`)
- `LOG_LEVEL`: Logging verbosity (default: `DEBUG`)

## Quick Start

### Prerequisites

- Docker Engine 20.10+
- Docker Compose v2.0+
- Network access to 5G Core PCF (if using real network)

### Running the Services

1. Clone this repository:
```bash
git clone <repository-url>
cd QoD-NCSRD
```

2. Switch to the docker-compose branch:
```bash
git checkout camara-nef-compose
```

3. Start both services:
```bash
docker-compose up -d
```

4. Verify services are running:
```bash
docker-compose ps
```

5. Check logs:
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f camara-qod
docker-compose logs -f nef-qos
```

### Stopping the Services

```bash
# Stop services
docker-compose down

# Stop and remove volumes
docker-compose down -v
```

## Configuration

### Custom QoS Profiles

Edit `docker-compose.yaml` to modify the `QOS_MAPPING` environment variable:

```yaml
QOS_MAPPING: >
  {
    "QOS_CUSTOM": {"marBwDl": "50 Mbps", "marBwUl": "10 Mbps", "mediaType": "VIDEO"}
  }
```

### PCF Connection

Update the PCF connection settings in `docker-compose.yaml`:

```yaml
environment:
  PCF_BASE_URL: "your.pcf.ip.address"
  PCF_PORT: "8086"
```

## Accessing the APIs

You can access each API respectively through:

- **NEF AsSessionWithQoS API**: `http://localhost:8585/docs` (Swagger UI)
- **CAMARA QoD API**: `http://localhost:8584/docs` (Swagger UI)
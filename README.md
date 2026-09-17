# RoutePulse

RoutePulse is a Python-based route optimization project designed for grocery and last-mile delivery operations. It helps a fulfillment center or dark store plan efficient delivery sequences for customer orders by calculating distances, estimating travel time, and minimizing route length before dispatch.

The project combines geospatial calculations, graph-based shortest-path logic, and a FastAPI backend to create a practical delivery-routing engine.

## Why this project exists

In delivery operations, poor stop ordering can lead to:
- longer travel distances
- increased fuel consumption
- slower customer delivery times
- unnecessary detours and route inefficiency

RoutePulse addresses these issues by optimizing the order in which deliveries are made, reducing the total route length and improving dispatch efficiency.

## Key features

- Distance calculation between GPS coordinates using the Haversine formula
- Distance matrix generation for multiple delivery points
- Route optimization using a nearest-neighbor TSP-style heuristic
- 2-opt route improvement to reduce crossing and detour problems
- ETA and cost estimation for travel and drop-off operations
- Shortest-path routing using Dijkstra's algorithm
- Geocoding support for address-to-coordinate conversion
- FastAPI-based backend for route and geospatial operations
- Sample data for Bengaluru-style delivery scenarios

## Project structure

```text
RoutePulse/
├── backend/
│   ├── __init__.py
│   ├── geo_utils.py
│   ├── main.py
│   └── algorithms/
│       ├── __init__.py
│       ├── dijkstra.py
│       ├── distance_matrix.py
│       └── tsp_solver.py
├── data/
│   ├── depots.json
│   └── sample_orders.json
├── tests/
│   ├── __init__.py
│   ├── test_api_phase1.py
│   └── test_phase1.py
├── .gitignore
├── pytest.ini
├── requirements.txt
├── run_phase1_demo.py
├── README.md
└── LICENSE
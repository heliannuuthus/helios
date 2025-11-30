#!/usr/bin/env python3
"""
Console scripts for Choosy Backend
"""
import uvicorn


def run_server():
    """Run the production server"""
    uvicorn.run("app.main:app", host="0.0.0.0", port=18000)


def run_dev_server():
    """Run the development server with auto-reload"""
    uvicorn.run("app.main:app", host="0.0.0.0", port=18000, reload=True)


if __name__ == "__main__":
    run_dev_server()

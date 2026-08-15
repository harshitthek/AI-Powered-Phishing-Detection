"""
Compatibility entrypoint for FastAPI Backend.
Re-exports the application from main.py.
"""
from main import app, analyze_single_email, EmailInput, PredictionResult

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)

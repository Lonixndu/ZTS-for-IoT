"""Start the local prototype using .env; a single persistent writer on port 8001."""
from pathlib import Path
import os
import uvicorn

if __name__ == '__main__':
    os.chdir(Path(__file__).resolve().parent)
    uvicorn.run('main:application', factory=True, host='127.0.0.1', port=8001, workers=1)

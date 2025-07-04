# incast-analysis

## Files

`analysis.ipynb`: ***[START HERE]*** This Jupyter Notebook contains the main analysis functionality for the incast bursts IMC paper. This notebook analyzes a single NS3 simulation from incast.cc. I recommend starting here, and using Jupyter Labs (instructions below) to view/edit this file.

`analysis.py`: This Python file is a copy of analysis.ipynb that is automatically created (by jupytext) when it is saved in Jupyter Labs. This process is required so that we can import the functions we write in analysis.ipynb into analyze_multiple.ipynb.

`analyze_multiple.ipynb`: This Jupyter Notebook uses the functionality in analysis.py to analyze many NS3 simulations and compare data between them.

`analyze_multiple.py`: This Python file is a copy of analyze_multiple.ipynb that is automatically created (by jupytext) when it is saved in Jupyter Labs. This is currently not used.

## Setup

```
git clone git@github.com:cmu-snap/incast-analysis
cd incast-analysis
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade -r requirements.txt
jupyter lab
```

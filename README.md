# incast-analysis

## Paper: _Understanding Incast Bursts in Modern Datacenters_
Christopher Canel, Balasubramanian Madhavan, Srikanth Sundaresan, Neil Spring, Prashanth Kannan, Ying Zhang, Kevin Lin, and Srinivasan Seshan. 2024. Understanding Incast Bursts in Modern Datacenters. In Proceedings of the 2024 ACM on Internet Measurement Conference (IMC '24). Association for Computing Machinery, New York, NY, USA, 674–680. https://doi.org/10.1145/3646547.3689028

## Files
- `analysis.ipynb`: ***[START HERE]*** This Jupyter Notebook contains the main analysis functionality for the incast bursts IMC paper. This notebook analyzes a single NS3 simulation from incast.cc. I recommend starting here, and using Jupyter Labs (instructions below) to view/edit this file.
  - In Cell 2, set "EXP_DIR" to an output directory from incast.cc.
- `analysis.py`: This Python file is a copy of analysis.ipynb that is automatically created (by jupytext) when it is saved in Jupyter Labs. This process is required so that we can import the functions we write in analysis.ipynb into analyze_multiple.ipynb.
- `analyze_multiple.ipynb`: This Jupyter Notebook uses the functionality in analysis.py to analyze many NS3 simulations and compare data between them. Note that this is currently designed to analyze a set of experiments with the same burst duration, since that is how we presented the results in the IMC paper. 
  - Towards the bottom, set "SWEEP_DIR" to a directory containing many output directories from incast.cc.
- `analyze_multiple.py`: This Python file is a copy of analyze_multiple.ipynb that is automatically created (by jupytext) when it is saved in Jupyter Labs. This is currently not used.

## Setup
```
git clone git@github.com:cmu-snap/incast-analysis
cd incast-analysis
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade -r requirements.txt
jupyter lab
```

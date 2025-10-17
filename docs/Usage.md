# Toolio Usage Notes

## Basic Scan
```bash
python3 toolio.py --targets scanme.nmap.org --ports 22,80,443
```
## Scan with top 100 ports and custom flags
```
python3 toolio.py --targets-file targets.txt --top-ports 100 --scan-type "-sS -Pn" --threads 4
```

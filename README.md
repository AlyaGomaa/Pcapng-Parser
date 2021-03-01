# Pcapng-Parser

### Installation
bitsbehumble library (my library) is required to do the hex and bytes coversions
```pip install -r requirements.txt```

### Usage:

to add a comment text  : 

```python3 editor.py <pcapngfile> <packetnumber> <comment>```

```python3 editor.py sample.pcapng 1 "Hello"```

to read a comment      : 

```python3 editor.py <pcapngfile> <packetnumber>```

```python3 editor.py sample.pcapng 1```


# Pcapng-Parser

### Installation
bitsbehumble library (my library) is required to do the hex and bytes coversions
```pip install -r requirements.txt```

### Usage:

to add a comment text  : 

```editor.py <pcapngfile> <packetnumber> <comment>```

```editor.py sample.pcapng 1 "Hello"```

to read a comment      : 

```editor.py <pcapngfile> <packetnumber>```

```editor.py sample.pcapng 1```


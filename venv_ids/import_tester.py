try:
    import scapy
    import pandas
    import numpy
    import matplotlib
    import seaborn
    import flask
    import sqlalchemy
    import psycopg2
    import sklearn
    print("all packages are installed")
except ImportError as e:
    print(f"{e.name} is not installed")

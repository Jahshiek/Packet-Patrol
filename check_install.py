try:
    import pandas
    import scapy
    import numpy
    import matplotlib
    import seaborn
    import flask
    import sqlalchemy
    import psycopg2
    import sklearn
    print("all packages are found")
except ImportError as e:
    print(f"cant find {e.name}")

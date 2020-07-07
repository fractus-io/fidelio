import streamlit as st
import pandas as pd
import numpy as np

def main():
    cves = get_data()
    st.title('Welcome to the Fidelio Visualizer')
    st.dataframe(cves['vendor'])


@st.cache
def get_data():
    df = pd.read_csv('../cve.csv')
    return df


if __name__ == "__main__":
    main()

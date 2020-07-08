import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
import datetime as dt

def main():
    cves = get_data()
    st.title('Welcome to the Fidelio Visualizer')

    draw_graph3(cves)
    draw_graph2(cves)
    draw_graph1(cves)

def draw_graph3(data):
    cves = data
    bases = pd.DataFrame(columns=['range', 'base'])
    for i, j in enumerate(range(1, 11)):
        filt = (cves['cvss_base'] > i) & (cves['cvss_base'] < j)

        bases = bases.append({'range': f'{i}-{j}', 'base': cves['cvss_base'].loc[filt].count()}, ignore_index=True)

    fig = px.bar(bases, x='range', y='base', color='range', labels={'range': 'Base Score', 'base': 'Number of CVEs'})
    st.plotly_chart(fig)


def draw_graph2(data):
    cves = data

    vendors = cves['vendor'].value_counts()
    vendor_list = []
    for vendor in vendors[:20]:
        vendor_list.append(vendor)

    fig = px.bar(vendors.iloc[:20], y='vendor', labels={'vendor': 'Number of CVEs', 'index': 'Vendor'})
    st.plotly_chart(fig)


def draw_graph1(data):
    cves = data

    years = cves['published_date'].dt.year.unique()
    severity_high = []
    severity_medium = []
    severity_low = []

    for year in years:

        high = cves['cvss_severity'].loc[cves['published_date'].dt.year == year].value_counts().loc['HIGH']
        medium = cves['cvss_severity'].loc[cves['published_date'].dt.year == year].value_counts().loc['MEDIUM']
        low = cves['cvss_severity'].loc[cves['published_date'].dt.year == year].value_counts().loc['LOW']

        severity_high.append(high)
        severity_medium.append(medium)
        severity_low.append(low)

    
    fig = go.Figure(data=[
    go.Bar(name='High', x=years, y=severity_high),
    go.Bar(name='Medium', x=years, y=severity_medium),
    go.Bar(name='Low', x=years, y=severity_low)
    ])
    fig.update_layout(barmode='group')
    st.plotly_chart(fig)


@st.cache
def get_data():
    df = pd.read_csv('../cve.csv', parse_dates=['published_date'])
    return df


if __name__ == "__main__":
    main()

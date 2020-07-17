import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import datetime as dt
from os.path import isfile
from sqlalchemy import create_engine
import psycopg2
import os


def main():

    csv_check = st.sidebar.checkbox('Use your csv files')

    if csv_check:
        if isfile('cve.csv'):
            cpes = get_csv('cve.csv')
        else:
            cpes = get_csv('cve_sample.csv')
        cves = cpes.loc[~cpes['cve_id'].duplicated(keep='first')]
        # st.write(cves.head(20))

    else:
        cves = get_data('CVE')
        cpes = get_data('CPE')

    st.title('Welcome to the Fidelio Visualizer')
    st.write('A Streamlit Application used for the visualization of Common Vulnerabilities and Exposures.')

    # st.dataframe(cpes['vendor_id'].value_counts().index)

    cve_number_time(cves)
    cve_number_year(cves)
    cve_number(cves)
    cve_scores(cves)
    if csv_check:
        cpe_number_product_csv(cpes)
        cpe_number_vendor_csv(cpes)
    else:
        cpe_number_product(cpes)
        cpe_number_vendor(cpes)


def cve_number_time(data):
    cves = data
    select = st.sidebar.selectbox('Time options', ['Last week', 'Last 30 days', 'Last 90 days', 'Last year', 'All time'])

    dates = cves['published_date'].dt.date.sort_values().unique()

    if select == 'Last week':
        from_value = dates[-1] - dt.timedelta(days=6)
        to_value = dates[-1]
    elif select == 'Last 30 days':
        from_value = dates[-1] - dt.timedelta(days=30)
        to_value = dates[-1]
    elif select == 'Last 90 days':
        from_value = dates[-1] - dt.timedelta(days=90)
        to_value = dates[-1]
    elif select == 'Last year':
        from_value = dates[-1] - dt.timedelta(days=365)
        to_value = dates[-1]
    elif select == 'All time':
        from_value = dates[1]
        to_value = dates[-1]

    date = st.sidebar.date_input("From", min_value=dates[1],
                                 max_value=dates[-2],
                                 value=[from_value, to_value])

    try:
        fig = go.Figure(data=go.Scatter(y=cves['published_date'].dt.date.value_counts().sort_index().loc[date[0]:date[1]],
                                        x=cves['published_date'].dt.date.value_counts().sort_index().loc[date[0]:date[1]].index
                                        ))
        fig.update_layout(title='Number of CVEs by Time',
                          xaxis_title='Date',
                          yaxis_title='Number of CVEs')
        fig.update_traces(hoverinfo='x+y', hovertemplate='%{x} <extra>%{y}</extra>')
        st.plotly_chart(fig)
    except IndexError:
        st.error('Please select a date range.')


def cpe_number_product(data):
    cpes = data

    display = st.sidebar.slider('Number of Products', 1, 25, 10)

    vendors = cpes['product_id'].value_counts()
    vendor_names = get_data('product')

    vendor_names_list = vendor_names[vendor_names['id'].isin(vendors.iloc[:display].index)]
    vendor_names_list.set_index(vendor_names_list['id'], inplace=True)
    vendor_names_list['count'] = vendors.iloc[:display]
    vendor_names_list.sort_values('count', ascending=False, inplace=True)

    fig = px.bar(vendor_names_list, x='count', y='name',
                 labels={'count': 'Number of CVEs', 'name': 'Product'}, text='count')
    fig.update_traces(texttemplate='%{text:.2s}', textposition='outside',
                      hovertemplate='%{x} <extra></extra>')
    fig.update_layout(uniformtext_minsize=8, uniformtext_mode='hide', title='Total Number of Vulnerabilities by Product')
    st.plotly_chart(fig)


def cpe_number_product_csv(data):
    cves = data

    display = st.sidebar.slider('Number of Products', 1, 25, 10)

    products = cves['product'].value_counts()
    product_list = []
    for product in products[:display]:
        product_list.append(product)

    fig = px.bar(products.iloc[:display], x='product',
                 labels={'product': 'Number of CVEs', 'index': 'Product'}, text='product')
    fig.update_traces(texttemplate='%{text:.2s}', textposition='outside',
                      hovertemplate='%{x} <extra></extra>')
    fig.update_layout(uniformtext_minsize=8, uniformtext_mode='hide', title='Total Number of Vulnerabilities by Product')
    st.plotly_chart(fig)


def cve_number(data):
    cves = data

    display, select = select_option('graph4')
    value = cves[f'{display}'].value_counts()
    try:
        first_value = [value.iloc[0]]
        first_value_index = value.index[0]
    except IndexError:
        first_value = [0]
        first_value_index = 'Value is 0'
    try:
        second_value = [value.iloc[1]]
        second_value_index = value.index[1]
    except IndexError:
        second_value = [0]
        second_value_index = 'Value is 0'
    try:
        third_value = [cves[f'{display}'].value_counts().iloc[2]]
        third_value_index = value.index[2]
    except IndexError:
        third_value = [0]
        third_value_index = "Value is 0"
    # st.write(cves[f'{display}'].value_counts())

    try:
        fig = go.Figure(data=[
            go.Bar(name=first_value_index, y=first_value, hoverinfo='y+name', text=first_value),
            go.Bar(name=second_value_index, y=second_value, hoverinfo='y+name', text=second_value),
            go.Bar(name=third_value_index, y=third_value, hoverinfo='y+name', text=third_value)
        ])

        fig.update_layout(barmode='group', height=475, title=f'Total number of Vulnerabilities by {select}')
        fig.update_traces(textposition='outside', hoverinfo='y+name')
        fig.update_xaxes(showticklabels=False)

        st.plotly_chart(fig)
        cve_number_pie(cves, display)

    except IndexError:
        st.error('There is not enough data to make this graph')


def cve_number_pie(data, display):
    cves = data

    fig = go.Figure(data=[go.Pie(
        labels=cves[f'{display}'].value_counts().index,
        values=cves[f'{display}'].value_counts())])
    st.plotly_chart(fig)


def cve_scores(data):
    cves = data

    select = st.selectbox('Select what to display', ['Base Score', 'Impact Score', 'Exploit Score'])

    if select == 'Base Score':
        score = 'cvss_base'
    elif select == 'Impact Score':
        score = 'cvss_impact'
    elif select == 'Exploit Score':
        score = 'cvss_exploit'

    scores = pd.DataFrame(columns=['range', 'score'])
    for i, j in enumerate(range(1, 11)):
        filt = (cves[f'{score}'] > i) & (cves[f'{score}'] < j)

        scores = scores.append({'range': f'{i}-{j}', 'score': cves[f'{score}'].loc[filt].count()}, ignore_index=True)

    fig = px.bar(scores, x='range', y='score', color='range',
                 labels={'range': select, 'score': 'Number of CVEs'},
                 title=f'Total number of Vulnerabilities by {select}')

    fig.update_traces(texttemplate='%{y}', textposition='outside')
    st.plotly_chart(fig)


def cpe_number_vendor(data):
    cpes = data

    display = st.sidebar.slider('Number of Vendors', 1, 25, 10)

    vendors = cpes['vendor_id'].value_counts()
    vendor_names = get_data('vendor')

    vendor_names_list = vendor_names[vendor_names['id'].isin(vendors.iloc[:display].index)]
    vendor_names_list.set_index(vendor_names_list['id'], inplace=True)
    vendor_names_list['count'] = vendors.iloc[:display]
    vendor_names_list.sort_values('count', ascending=False, inplace=True)

    fig = px.bar(vendor_names_list, x='count', y='name',
                 labels={'count': 'Number of CVEs', 'name': 'Vendor'}, text='count')
    fig.update_traces(texttemplate='%{text:.2s}', textposition='outside',
                      hovertemplate='%{x} <extra></extra>')
    fig.update_layout(uniformtext_minsize=8, uniformtext_mode='hide', title='Total Number of Vulnerabilities by Vendor')
    st.plotly_chart(fig)


def cpe_number_vendor_csv(data):
    cves = data

    display = st.sidebar.slider('Number of Vendors', 1, 25, 10)

    vendors = cves['vendor'].value_counts()
    vendor_list = []
    for vendor in vendors[:display]:
        vendor_list.append(vendor)

    fig = px.bar(vendors.iloc[:display], x='vendor',
                 labels={'vendor': 'Number of CVEs', 'index': 'Vendor'}, text='vendor', )
    fig.update_traces(texttemplate='%{text:.2s}', textposition='outside',
                      hovertemplate='%{x} <extra></extra>')
    fig.update_layout(uniformtext_minsize=8, uniformtext_mode='hide', title='Total Number of Vulnerabilities by Vendor')
    st.plotly_chart(fig)


def cve_number_year(data):
    cves = data

    display, select = select_option('graph1')
    years = cves['published_date'].dt.year.unique()
    first_list = []
    second_list = []
    third_list = []

    bar_mode = 'group' if len(years) < 6 else 'stack'

    for year in years:
        # st.write(cves[f'{display}'].loc[cves['published_date'].dt.year == year].value_counts())
        try:
            first_value = cves[f'{display}'].loc[cves['published_date'].dt.year == year].value_counts().sort_index(ascending=False).iloc[0]
        except IndexError:
            first_value = 0
        try:
            second_value = cves[f'{display}'].loc[cves['published_date'].dt.year == year].value_counts().sort_index(ascending=False).iloc[1]
        except IndexError:
            second_value = 0
        try:
            third_value = cves[f'{display}'].loc[cves['published_date'].dt.year == year].value_counts().sort_index(ascending=False).iloc[2]
        except IndexError:
            third_value = 0

        first_list.append(first_value)
        second_list.append(second_value)
        third_list.append(third_value)

    try:
        fig = go.Figure(data=[
            go.Bar(name=cves[f'{display}'].value_counts().sort_index(ascending=False).index[0], x=years, y=first_list, text=first_list),
            go.Bar(name=cves[f'{display}'].value_counts().sort_index(ascending=False).index[1], x=years, y=second_list, text=second_list),
            go.Bar(name=cves[f'{display}'].value_counts().sort_index(ascending=False).index[2], x=years, y=third_list, text=third_list)
        ])
        fig.update_layout(barmode=bar_mode, height=475, title=f'Total number of Vulnerabilities by {select} by year',
                          uniformtext_minsize=8, uniformtext_mode='hide')
        fig.update_traces(textposition='outside', hoverinfo='y+name')
        st.plotly_chart(fig)
    except IndexError:
        st.error('There is not enough data to make this graph')


def select_option(key):
    select = st.selectbox('Select what to display', [  # 'Severity',
                          'Access Complexity', 'Access Vector',
                          'Access Authentication', 'Confidentiality Impact',
                          'Integrity Impact', 'Availability Impact'], key=key)

    if select == 'Access Complexity':
        display = 'cvss_access_complexity'
    elif select == 'Access Vector':
        display = 'cvss_access_vector'
    elif select == 'Access Authentication':
        display = 'cvss_access_authentication'
    elif select == 'Confidentiality Impact':
        display = 'cvss_confidentiality_impact'
    elif select == 'Integrity Impact':
        display = 'cvss_integrity_impact'
    elif select == 'Availability Impact':
        display = 'cvss_availability_impact'
    # elif select == 'Severity':
    #     display = 'cvss_severity'
    return display, select


@st.cache
def get_data(table):
    engine = create_engine(f'postgresql://{os.environ.get("FIDELIO_USER")}:{os.environ.get("FIDELIO_PASS")}@46.101.210.113/fidelio')
    df = pd.read_sql(f'{table}', engine)
    return df


@st.cache
def get_csv(csv_file):
    df = pd.read_csv(csv_file, parse_dates=['published_date'])
    return df


if __name__ == "__main__":
    main()

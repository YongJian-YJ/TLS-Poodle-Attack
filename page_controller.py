# conda activate chat-with-website
# streamlit run page_controller.py

import streamlit as st

# Server browser page
Server = st.Page(
    page="views/server.py",
    title="Server Page",
    icon=":material/account_circle:",
)

# Client browser page
Alice = st.Page(
    page="views/Alice.py",
    title="Account Registration Page",
    icon=":material/account_circle:",
    default=True,  # to set this as FIRST page upon establishing connection
)

# Attacker browser page
Eve = st.Page(
    page="views/Eve.py",
    title="Eve's Control Page",
    icon=":material/account_circle:",
)

# To go between the different pages
pg = st.navigation(pages=[Server, Alice, Eve])

pg.run()

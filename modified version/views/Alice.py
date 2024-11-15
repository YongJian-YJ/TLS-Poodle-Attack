# conda activate chat-with-website
# streamlit run Alice.py

import streamlit as st

st.header("Alice's Control Page")

# Initialize the session state variable for the message if it doesn't exist
if "message" not in st.session_state:
    st.session_state["message"] = ""

# Create a textbox for Alice to type the message
message_input = st.text_input("Enter your message:", value=st.session_state["message"])

# Create a button to send the message
if st.button("Send Message"):
    # Save the message to the session state when the button is pressed
    st.session_state["message"] = message_input
    st.success("Message sent!")

# Display the message if it has been sent
if st.session_state["message"]:
    st.write(f"Message: {st.session_state['message']}")

import streamlit as st

# Set the title for the page
st.title("Server Page")

# Create a placeholder to display the message
message_placeholder = st.empty()

# Create a "Refresh" button
if st.button("Refresh"):
    # Display the message from session state when the button is pressed
    if "message" in st.session_state and st.session_state["message"]:
        message_placeholder.write(f"Message from Alice: {st.session_state['message']}")
    else:
        message_placeholder.write("No message received yet.")

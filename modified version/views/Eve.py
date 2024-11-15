import streamlit as st

# Set the title for Eve's control page
st.title("Eve's Control Page")

# Create a section to display the message from Alice
st.subheader("Message from Alice:")

# Option to simulate interception (could alter or log message)
if st.button("Intercept Message"):
    # Simulate intercepting the message, for example by logging or modifying it
    intercepted_message = st.session_state["message"]  # Could modify this message
    st.session_state["intercepted_message"] = intercepted_message
    st.success(f"Intercepted Message: {intercepted_message}")

# Display a log of intercepted messages (if relevant)
if "intercepted_message" in st.session_state:
    st.subheader("Intercepted Message Log")
    st.write(f"Last Intercepted Message: {st.session_state['intercepted_message']}")

# Optional: Eve can modify the intercepted message before sending it forward
if "intercepted_message" in st.session_state:
    modified_message = st.text_input(
        "Modify the message before sending:", st.session_state["intercepted_message"]
    )
    if st.button("Send Modified Message"):
        st.session_state["message"] = modified_message
        st.success("Modified message sent to Server.")

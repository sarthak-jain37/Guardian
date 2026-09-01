import streamlit as st
import requests
from backend.app.core.config import BACKEND_URL


st.set_page_config(
    page_title="RBAC Drift Guardian",
    page_icon="🛡️",
    layout="wide",
)

st.title("Kubernetes RBAC Drift Guardian")


def get_events():

    try:
        response = requests.get(
            f"{BACKEND_URL}/outputs",
            timeout=5,
        )

        response.raise_for_status()

        return response.json().get(
            "events",
            []
        )

    except requests.RequestException as error:

        st.error(
            f"Backend connection failed: {error}"
        )

        return []


def render_diff(diff):

    for category, changes in diff.items():

        if not changes:
            continue

        is_added = "added" in category
        is_removed = "removed" in category

        title = category.replace(
            "_",
            " "
        ).title()

        if is_added:

            st.success(
                f"🟢 {title}"
            )

        elif is_removed:

            st.error(
                f"🔴 {title}"
            )

        else:

            st.warning(title)

        st.json(changes)


events = get_events()


if "current_index" not in st.session_state:

    st.session_state.current_index = 0


if not events:

    st.info(
        "No RBAC drift events detected yet."
    )

    st.stop()


# Make sure index remains valid
if (
    st.session_state.current_index
    >= len(events)
):

    st.session_state.current_index = (
        len(events) - 1
    )


# Navigation
left, middle, right = st.columns(
    [1, 2, 1]
)


with left:

    if st.button(
        "⬅ Previous",
        disabled=(
            st.session_state.current_index == 0
        ),
        use_container_width=True,
    ):

        st.session_state.current_index -= 1

        st.rerun()


with middle:

    st.markdown(
        f"""
        <div style="text-align:center;">
            <h4>
                Drift Event
                {st.session_state.current_index + 1}
                of
                {len(events)}
            </h4>
        </div>
        """,
        unsafe_allow_html=True,
    )


with right:

    if st.button(
        "Next ➡",
        disabled=(
            st.session_state.current_index
            == len(events) - 1
        ),
        use_container_width=True,
    ):

        st.session_state.current_index += 1

        st.rerun()


st.divider()


current_event = events[
    st.session_state.current_index
]


st.caption(
    f"Detected: "
    f"{current_event.get('timestamp', 'Unknown')}"
)


diff_col, llm_col = st.columns(2)


with diff_col:

    st.subheader(
        "🔐 RBAC Diff"
    )

    render_diff(
        current_event.get(
            "diff",
            {},
        )
    )


with llm_col:

    st.subheader(
        "LLM Analysis"
    )

    st.markdown(
        current_event.get(
            "llm_response",
            "No LLM analysis available.",
        )
    )
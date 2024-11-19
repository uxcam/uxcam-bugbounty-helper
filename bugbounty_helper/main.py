import json
import os

import streamlit as st
from cvss import CVSS3

st.set_page_config(page_title="UXCam Security - Bug Bounty Helper", layout="wide")


@st.cache_data
def load_json(filepath):
    with open(filepath) as f:
        return json.load(f)


vrt_version = "v1.14.2"
taxonomy_data = load_json(
    os.path.join("bugcrowd-vrt", vrt_version, "vulnerability-rating-taxonomy.json")
)
cvss_data = load_json(os.path.join("bugcrowd-vrt", vrt_version, "cvss_v3.json"))


@st.cache_data
def find_cvss_vector_and_priority(item_id, cvss_content, taxonomy_content):
    def find_in_cvss_content(item_id, content):
        for item in content:
            if item["id"] == item_id:
                return item.get("cvss_v3")
            if "children" in item:
                result = find_in_cvss_content(item_id, item["children"])
                if result:
                    return result
        return None

    def find_priority_in_taxonomy(item_id, content):
        for category in content:
            for sub in category.get("children", []):
                if sub["id"] == item_id:
                    return sub.get("priority")
                for variant in sub.get("children", []):
                    if variant["id"] == item_id:
                        return variant.get("priority")
        return None

    cvss_vector = find_in_cvss_content(item_id, cvss_content)
    priority = find_priority_in_taxonomy(item_id, taxonomy_content)
    return cvss_vector, priority


def get_categories(taxonomy_content):
    return {cat["id"]: cat["name"] for cat in taxonomy_content}


def get_subcategories(selected_category, taxonomy_content):
    for cat in taxonomy_content:
        if cat["id"] == selected_category:
            return {sub["id"]: sub["name"] for sub in cat.get("children", [])}
    return {}


def get_variants(selected_category, selected_subcategory, taxonomy_content):
    for cat in taxonomy_content:
        if cat["id"] == selected_category:
            for sub in cat.get("children", []):
                if sub["id"] == selected_subcategory:
                    return {var["id"]: var["name"] for var in sub.get("children", [])}
    return {}


st.title("Bugcrowd VRT <-> CVSS Mapping")
st.write(
    "An app to help us map Bugcrowd VRT to CVSS v3 vector/score; used for our bug bounty program. Check our bug bounty program at: https://uxcam.com/bug-bounty."
)
st.markdown(
    f"Bugcrowd VRT version: [{vrt_version}](https://github.com/bugcrowd/vulnerability-rating-taxonomy/releases/tag/{vrt_version})"
)
st.write("---")

col1, col2, col3 = st.columns(3)

with col1:
    categories = get_categories(taxonomy_data["content"])
    selected_category = st.selectbox(
        "VRT category", list(categories.keys()), format_func=lambda x: categories[x]
    )

subcategories = (
    get_subcategories(selected_category, taxonomy_data["content"])
    if selected_category
    else {}
)
with col2:
    selected_subcategory = (
        st.selectbox(
            "Specific vulnerability name",
            list(subcategories.keys()),
            format_func=lambda x: subcategories[x],
        )
        if subcategories
        else None
    )

variants = (
    get_variants(selected_category, selected_subcategory, taxonomy_data["content"])
    if selected_subcategory
    else {}
)
with col3:
    selected_variant = (
        st.selectbox(
            "Variant / Affected function",
            list(variants.keys()),
            format_func=lambda x: variants[x],
        )
        if variants
        else None
    )

selected_id = selected_variant or selected_subcategory

if selected_id:
    cvss_vector, priority = find_cvss_vector_and_priority(
        selected_id, cvss_data["content"], taxonomy_data["content"]
    )

    with st.container():
        st.subheader("CVSS v3 Calculation")

        if cvss_vector:
            cvss = CVSS3("CVSS:3.1/" + cvss_vector)
            base_score = cvss.base_score
            base_severity = cvss.severities()[0]
            clean_vector = cvss.clean_vector()
        else:
            base_score = base_severity = clean_vector = "N/A"

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric(
                label="VRT Priority", value=f"P{priority}" if priority else "Varies"
            )
        with col2:
            st.metric(label="Base Score", value=f"{base_score}")
        with col3:
            st.metric(label="Base Severity", value=f"{base_severity}")

        st.write("Summary")
        severity_color = {
            "Critical": st.error,
            "High": st.warning,
            "Medium": st.info,
            "Low": st.success,
        }.get(base_severity, st.success)
        severity_color(f"{clean_vector} ({base_score})")

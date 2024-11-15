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
    # Find CVSS vector
    cvss_vector = None
    for item in cvss_content:
        if item["id"] == item_id:
            cvss_vector = item.get("cvss_v3")
        elif "children" in item:
            cvss_vector = find_cvss_vector_and_priority(
                item_id, item["children"], taxonomy_content
            )[0]
        if cvss_vector:
            break

    # Find priority from taxonomy data
    priority = None
    for category in taxonomy_content:
        for sub in category.get("children", []):
            if sub["id"] == item_id:
                priority = sub.get("priority")
            for variant in sub.get("children", []):
                if variant["id"] == item_id:
                    priority = variant.get("priority")
    return cvss_vector, priority


st.title("Bugcrowd VRT <-> CVSS Mapping")

st.write(
    "This tool helps you find the CVSS v3 vector and VRT priority for a given VRT category, subcategory, or variant."
)
st.write("Bugcrowd VRT version: ", vrt_version)
st.write("---")

col1, col2, col3 = st.columns(3)

with col1:
    categories = {cat["id"]: cat["name"] for cat in taxonomy_data["content"]}
    selected_category = st.selectbox(
        "VRT category", list(categories.keys()), format_func=lambda x: categories[x]
    )

selected_subcategory = None
subcategories = {}
if selected_category:
    for cat in taxonomy_data["content"]:
        if cat["id"] == selected_category:
            subcategories = {sub["id"]: sub["name"] for sub in cat.get("children", [])}
            break

with col2:
    if subcategories:
        selected_subcategory = st.selectbox(
            "Specific vulnerability name",
            list(subcategories.keys()),
            format_func=lambda x: subcategories[x],
        )

selected_variant = None
variants = {}
if selected_subcategory:
    for sub in taxonomy_data["content"]:
        if sub["id"] == selected_category:
            for child in sub.get("children", []):
                if child["id"] == selected_subcategory:
                    variants = {
                        var["id"]: var["name"] for var in child.get("children", [])
                    }
                    break

with col3:
    if variants:
        selected_variant = st.selectbox(
            "Variant / Affected function",
            list(variants.keys()),
            format_func=lambda x: variants[x],
        )

# Determine ID to use for finding CVSS vector and VRT priority
selected_id = selected_variant or selected_subcategory

if selected_id:
    cvss_vector, priority = find_cvss_vector_and_priority(
        selected_id, cvss_data["content"], taxonomy_data["content"]
    )

    with st.container(border=True):
        st.subheader("CVSS v3 Calculation")

        if cvss_vector:
            cvss = CVSS3("CVSS:3.1/" + cvss_vector)
            base_score = cvss.base_score
            base_severity = cvss.severities()[0]
            clean_vector = cvss.clean_vector()
        else:
            cvss = "N/A"
            base_score = "N/A"
            base_severity = "N/A"
            clean_vector = "N/A"

        col1, col2, col3 = st.columns(3)
        with col1:
            priority = f"P{priority}" if priority else "N/A"
            col1.metric(label="VRT Priority", value=f"{priority}")
        with col2:
            col2.metric(label="Base Score", value=f"{base_score}")
        with col3:
            col3.metric(label="Base Severity", value=f"{base_severity}")

        st.write("Summary")
        if base_severity == "Critical":
            st.error(f"{clean_vector} ({base_score})")
        elif base_severity == "High":
            st.warning(f"{clean_vector} ({base_score})")
        elif base_severity == "Medium":
            st.info(f"{clean_vector} ({base_score})")
        elif base_severity == "Low":
            st.success(f"{clean_vector} ({base_score})")
        else:
            st.success(f"{clean_vector} ({base_score})")

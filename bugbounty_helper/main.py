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
def find_cvss_vector(item_id, cvss_content):
    for item in cvss_content:
        if item["id"] == item_id:
            return item.get("cvss_v3")
        if "children" in item:
            result = find_cvss_vector(item_id, item["children"])
            if result:
                return result
    return None


@st.cache_data
def find_priority(item_id, cvss_content):
    for item in cvss_content:
        if item["id"] == item_id:
            return item.get("cvss_v3")
        if "children" in item:
            result = find_cvss_vector(item_id, item["children"])
            if result:
                return result
    return None


st.title("CVSS Vector Viewer")

# Create three columns for categories, subcategories, and variants
col1, col2, col3 = st.columns(3)

# First column: Category selection
with col1:
    categories = {cat["id"]: cat["name"] for cat in taxonomy_data["content"]}
    selected_category = st.selectbox(
        "Select Category", list(categories.keys()), format_func=lambda x: categories[x]
    )

# Second column: Subcategory selection if available
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
            "Select Subcategory",
            list(subcategories.keys()),
            format_func=lambda x: subcategories[x],
        )

# Third column: Variant selection if available
selected_variant = None
variants = {}
if selected_subcategory:
    for sub in taxonomy_data["content"]:
        if sub["id"] == selected_category:
            for child in sub.get("children", []):
                if child["id"] == selected_subcategory:
                    # If the subcategory has children (variants), populate variants dict
                    variants = {
                        var["id"]: var["name"] for var in child.get("children", [])
                    }
                    break

with col3:
    if variants:
        selected_variant = st.selectbox(
            "Select Variant", list(variants.keys()), format_func=lambda x: variants[x]
        )

# Determine which ID to use for finding CVSS vector
selected_id = selected_variant or selected_subcategory

# Display CVSS vector if available
if selected_id:
    cvss_vector = find_cvss_vector(selected_id, cvss_data["content"])
    with st.container(border=True):
        if cvss_vector:
            st.write("VRT Priority: P1")

            cvss = CVSS3("CVSS:3.1/" + cvss_vector)
            st.write("**CVSS v3 Calculation:**")
            st.write(f"Vector: {cvss_vector}")
            st.write(f"Base Score: {cvss.base_score}")
            st.write(f"Base Severity: {cvss.severities()[0]}")

            st.info(f"{cvss.clean_vector()} ({cvss.base_score})")
        else:
            st.warning("No CVSS vector available for this selection.")


st.header("Add logic to display priority as well")

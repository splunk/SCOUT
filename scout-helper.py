"""
Python Script Name: scout-helper.py
Author: Teoderick Contreras, Splunk Threat Research Team (STRT)
Date: 03-11.2025
version: 0.1
Description:
scout-helper.py is the primary Python script that enables users to select and execute specific tasks related to SCOUT tool configuration and security data processing.

Available Tasks:
Configure the SCOUT tool.
Generate a dataframe from Splunk Security Content.
Assist with correlation analysis.
Generate pre-configured correlations based on either an analytic story or a MITRE ATT&CK Technique ID.
"""

import streamlit as st
import pandas as pd
from PIL import Image
from pathlib import Path


from utility.UtilityHelper import HelperUtility
from utility.ConfigTask import ConfigUtility
from utility.GenerateDataTask import GenerateDataUtility
from utility.CorrelTask import CorrelationUtility
from utility.PreProcessTask import PreProcessUtility

st.set_page_config(page_title="Skee-H", page_icon = "🛡️", layout="wide")

hu = HelperUtility()
cu = ConfigUtility()
gu = GenerateDataUtility()
cru = CorrelationUtility()
ppu = PreProcessUtility()

def scch():
    hu.show_banner()
    tab1, tab2, tab3, tab4, tab5 = st.tabs(["Configuration", "Generate Data", "Correlation Helper", "Correlation by Analytic Story", "Correlation by Mitre Att&ck Technique ID"])
    
    with tab1:
        
        cu.config_setup()

    with tab2:
        gu.generate_data()

    with tab3:
        cru.content_helper_main()

    with tab4:
        st.warning('Warning: Due to the large volume of analytics story, processing from the Splunk Security Content GUI may result in slower output load times. We suggest going to the **:orange[output]** folder where the generated correlation searches are located after running this task or feature.', icon="⚠️")

        click_analytic_story_button = st.button("Generate Correlation Search by analytic story", type="primary")
        if click_analytic_story_button:
            ppu.pre_process_by_analytic_story()
    with tab5:
        st.warning('Warning: Due to the large volume of Mitre Att&ck Technique ID, processing from the Splunk Security Content GUI may result in slower output load times. We suggest going to the **:orange[output]** folder where the generated correlation searches are located after running this task or feature.', icon="⚠️")

        click_attack_id_button = st.button("Generate Correlation Search by mitre attack id", type="primary")
        if click_attack_id_button:
            ppu.pre_process_by_mitre_attack_tid()

    return


    
def main(): 


    page_names_to_funcs = {
        "skee-H": scch

    }
    demo_name = st.sidebar.selectbox("**:blue[Tasks:]**", page_names_to_funcs.keys())
    page_names_to_funcs[demo_name]()

    return


if __name__ == "__main__":
    main()

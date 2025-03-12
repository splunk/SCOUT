"""
Python Script Name: ConfigTask.py
Author: Teoderick Contreras
Date: 03-11.2025
version: 0.1
Description:
This module of the scout-helper Python tool is designed for managing its configuration settings, ensuring seamless integration and functionality.

Key Configuration Settings:

    - Splunk Security Content project path : Defines the location of the Splunk Security Content repository.
    - ATT&CK CTI project path              : Specifies the directory for the MITRE ATT&CK CTI data.
    - Correlation search templates         : Manages predefined templates for correlation searches.
    - Correlation fields configuration     : Handles field mappings and settings for correlation logic.
"""

from pathlib import Path
import streamlit as st
import os
import yaml
from utility.UtilityHelper import HelperUtility


class ConfigUtility:

    def __init__(self):
        self.curdir = os.getcwd()
        self.hu = HelperUtility()
        return



    def config_setup(self)->None:

        with st.container(border=True):
            st.markdown("### **:blue[Configuration]**")
            
            ### initialize session state of toggle
            st.session_state.disabled = True

            ## enable/ disable edit configuration
            edit_conf_toggle = st.toggle(":blue[Toggle Edit]", help="Edit Configuration", key = "enable_config_edit")

            if edit_conf_toggle:
                st.session_state.disabled = False
            col1, col2 = st.columns(2)

            with col1:
                with st.container(border=True):
                    ## parse and update security content folder path
                    self.hu.wrapper_get_update_config_field('security_content_detection_dir_path', st.session_state.disabled)

                    ## parse and update attackcti_repo_dir_path
                    self.hu.wrapper_get_update_config_field('attackcti_repo_dir_path', st.session_state.disabled)

                    ## parse and update security_content_story_path
                    self.hu.wrapper_get_update_config_field('security_content_story_dir_path', st.session_state.disabled)

                    ## parse and update default_author
                    self.hu.wrapper_get_update_config_field('default_author', st.session_state.disabled)
                
                with st.container(border=True):
                    ## parse and update correlation_filter_fields
                    self.hu.wrapper_get_update_config_field('correlation_filter_fields', st.session_state.disabled, "correlation")

                    self.hu.wrapper_get_update_config_field('correlation_output_dir', st.session_state.disabled, "correlation")

                    self.hu.wrapper_get_update_config_field('correlation_output_dir_by_story', st.session_state.disabled, "correlation")

                    self.hu.wrapper_get_update_config_field('correlation_output_dir_by_tag', st.session_state.disabled, "correlation")                         

                    self.hu.wrapper_get_update_config_field('correlation_yml_template_file_path', st.session_state.disabled, "correlation") 

            with col2:
                with st.container(border=True):

                    ### choose template
                    cor_search_name_list = self.hu.read_config_settings("cor_search_name_list", "correlation")
                    chosen_corr_search_template = st.selectbox("choose correlation search template", options=cor_search_name_list, help= "correlation search templates")

                    correlation_templt = self.hu.read_config_settings(chosen_corr_search_template, "correlation")

                    self.hu.update_config_field('correlation_template', correlation_templt, st.session_state.disabled)

                    if st.session_state.disabled == True:
                        code_block_val = self.hu.get_config_code_value( 'correlation_template', st.session_state.disabled, "splunk-spl")

                    if st.session_state.disabled == False:

                        code_block_val = st.text_area("correlation template", correlation_templt, disabled= st.session_state.disabled, height = 500)
                        self.hu.update_config_field('customized_correlation_template', code_block_val, st.session_state.disabled)


        return           
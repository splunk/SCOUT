"""
Python Script Name: CorrelTask.py
Author: Teoderick Contreras, Splunk Threat Research Team (STRT)
Date: 03-11.2025
version: 0.1
Description:
This module of the scout-helper Python tool manages Splunk correlation searches by leveraging security content, 
user-defined field filters, and preconfigured correlation templates from the settings.
"""

import streamlit as st
import yaml
import json
import pandas as pd
from PIL import Image
from pathlib import Path
import chardet
import os
import sys
import shutil
from attackcti import attack_client
from collections import defaultdict
from datetime import date
import uuid
import time


from utility.UtilityHelper import HelperUtility

class CorrelationUtility:

    def __init__(self):
        self.curdir = os.getcwd()
        self.HOME_PATH = Path.home()
        self.hu = HelperUtility()
        self.config = self.hu.load_config()
        self.chosen_cor_yml_file = ""

        return
    
    def get_chosen_cor_yml_file(self):
        return self.chosen_cor_yml_file
    
    def content_helper_main(self):
        
        json_df = self.hu.json_to_df(self.hu.get_generated_sec_con_json_path())
        if json_df.empty:
            st.error("jason_df is None, cannot access field_name.")
            return
        col_names = self.hu.dataframe_column_to_list(json_df)

        FILTERED_DF = json_df

        corr_option_val_dict = {}
        corr_option_substr_dict = {}  
        perc_ = self.hu.read_config_settings('source_count_perc',"correlation")
        corr_template = self.hu.read_config_settings('correlation_template')

        col1, col2 = st.columns((1, 3))

        with col2:
            with st.expander("**:blue[security content data frame]**"):
                st.dataframe(json_df,use_container_width=True)       
        with col1:
            corr_fields_value = self.hu.read_config_settings('correlation_filter_fields',"correlation")
            corr_fields_value = [v.strip() for v in corr_fields_value]

            field_value_out_dict = self.correlation_basic_settings()

            st.divider() 

            click_filter_button0 = st.button("run field filters", type="primary", key = "filter_button0")
            
            with st.expander("Correlation Helper Filter"):
                for field_name in corr_fields_value:
                    
                    selected = st.multiselect('Filter by {}:'.format(field_name), json_df[field_name].explode().dropna().unique())
                    selected = [str(value) for value in selected if value is not None]  # Filter out None values
                    corr_option_val_dict[field_name] = selected

            ### show the overall data frame after filtering out all chosen filters
            with st.expander("Filter by Sub-String"):
                corr_substr = self.hu.read_config_settings('correlation_filter_substr','correlation')
                corr_substr = [v.strip() for v in corr_substr]
                for f in corr_substr:
                    corr_option_substr_dict[f] = [a.strip() for a in st.text_input("filter {} by sub-string: ".format(f)).split(",") if a!=""]


            click_filter_button = st.button("run field filters", type="primary", key = "filter_button")


        with col2:
            FILTERED_DF, corr_option_val_dict_ = self.hu.filter_data_frame(FILTERED_DF, corr_option_val_dict)
            FILTERED_DF, corr_option_substr_dict_ = self.hu.filter_data_frame(FILTERED_DF, corr_option_substr_dict)

            with st.expander("Set of Overall Filtered DataFrame"):
                self.hu.count_detection_type(FILTERED_DF)
                st.dataframe(FILTERED_DF,width=1000, height=600)                      

            count_val = int(len(FILTERED_DF)*float(perc_))
            if int(len(FILTERED_DF)) == 1 or count_val <= 1:
                ## if the threshold percentage is too low of the number of detection is too low make the threshold * 2
                ## example if threshold is = 0.20 then it will be 0.20 * 2 = 0.40
                count_val = int(len(FILTERED_DF)*float(perc_ * 2)) 
            else:
                pass

            merge_dict = self.hu.merge_dicts(corr_option_val_dict, corr_option_substr_dict)
            
            updated_correlation_search = self.generate_splunk_search_condition(str(count_val), corr_template, merge_dict)
        
            with col1:
                ### show correlation addition settings and generate a yml file
                with st.expander("**:blue[Correlation Settings:]**"):
                    self.setup_filter_correlation_yml(FILTERED_DF, updated_correlation_search, field_value_out_dict)

            if click_filter_button or click_filter_button0:
                open_file = self.hu.get_cor_file_path()
            else:
                open_file = os.path.join(self.hu.get_correlation_output_dir_path(), self.get_chosen_cor_yml_file())
            
            with open (self.hu.expand_path(open_file), "r") as f:
                corr_yml_buff = f.read()

            st.success(f"**:blue[Generated Correlation YML:]**")

            st.code(corr_yml_buff,language="yaml", line_numbers=True)

        return

    def check_create_dir(self)->None:
        if not os.path.exists(self.hu.get_correlation_output_dir_path()):
            os.makedirs(self.hu.get_correlation_output_dir_path())
        if not os.path.exists(self.hu.get_correlation_output_path_by_tag()):
            os.makedirs(self.hu.get_correlation_output_path_by_tag())
        if not os.path.exists(self.hu.get_correlation_output_path_by_story()):
            os.makedirs(self.hu.get_correlation_output_path_by_story())
        return

    def correlation_basic_settings(self):
        field_value_out_dict = {}

        with st.expander("**:blue[Correlation Settings:]**"):
            st.session_state.disabled = False
            cor_template_file_path = self.hu.get_correlation_yml_template_file_path()
            field_value_out_dict["cor_template_file_path"] = cor_template_file_path

            ## copy the correlation templay yml file to the output folder of gen correlation yml
            self.check_create_dir()

            shutil.copy(cor_template_file_path, self.hu.get_correlation_output_dir_path())
            
            self.hu.generate_config_input_box(self.config, "author name", "default_author", field_value_out_dict)
            self.hu.generate_config_input_box(self.config, "correlation output path", "correlation_output_dir", field_value_out_dict, "correlation")
            self.hu.generate_config_input_box(self.config, "correlation name", "correlation_yml_name", field_value_out_dict, "correlation")

            self.hu.generate_config_input_box(self.config, "attack data link", "default_corr_data", field_value_out_dict, "correlation")
            self.hu.generate_config_input_box(self.config, "description", "correlation_description", field_value_out_dict, "correlation")


            self.chosen_cor_yml_file =  st.text_input(":blue[**Initial Correlation Template File Path:**]",value = self.hu.get_correlation_yml_template_file_path(), key = "init_template_val",disabled=True)
            field_value_out_dict['chosen_file'] = self.chosen_cor_yml_file
        return field_value_out_dict
    
    def generate_splunk_search_condition(self, str_row_len:str, correlation_template:str, filter_values_dict:dict)->str:
        ## detection type is still not supported in correlation search so im popping it out
        
        if 'type' in filter_values_dict:
            filter_values_dict.pop('type')
        updated_correlation_search = correlation_template
        temp_conditional_search = ""

        for tag_name, filter_values in filter_values_dict.items():
            if not self.hu.check_empty_list(filter_values) or updated_correlation_search == "":
                continue
            else:
                temp_conditional_search += "{} IN ({}) ".format(self.hu.read_config_settings(tag_name, "common_field_name"), ", ".join(["\"*{}*\"".format(s) for s in filter_values]))

                updated_correlation_search = correlation_template.replace("<<condition_splunk_search>>", temp_conditional_search)

        with st.expander('generated correlation search'):
            updated_correlation_search = updated_correlation_search.replace("<<threshold_value>>", str(self.hu.read_config_settings("source_count_perc", "correlation")))

            updated_correlation_search = updated_correlation_search.replace("<<source_count_condition>>", str_row_len)

            newline_updated_correlation_search = updated_correlation_search.replace(", ", ", \n").replace(" by", "\n by").replace("| ", "\n| ")

            st.code(newline_updated_correlation_search, language='splunk-spl', line_numbers=True)

        return updated_correlation_search
    
    def setup_filter_correlation_yml(self, FILTERED_DF, updated_correlation_search, field_value_out_dict):
    

        ### lets fill the template yml file
        with open(field_value_out_dict["cor_template_file_path"], "r") as f:
            corr_yml_buff = yaml.safe_load(f)
        
        ## update date, id, author
        corr_yml_buff['id'] = str(uuid.uuid4())
        corr_yml_buff['date'] = date.today().strftime('%Y-%m-%d')
        corr_yml_buff['author'] = field_value_out_dict["default_author"]
        corr_yml_buff['name'] = field_value_out_dict["correlation_yml_name"]

        ### update mitre attack id by grabbing the unique value of story in filtered dataframe and convert it to list
        combined_analytic_story = []
        [combined_analytic_story.extend(sublist) for sublist in [corr_story.strip("[]").replace("'","").split(", ") for corr_story in FILTERED_DF['tags.analytic_story'].astype(str).dropna().unique().tolist()]]
        corr_yml_buff['tags']['analytic_story'] = list(set(combined_analytic_story))

        ### update references
        combined_references = []
        [combined_references.extend(sublist) for sublist in [corr_reff.strip("[]").replace("'","").split(", ") for corr_reff in FILTERED_DF['references'].astype(str).dropna().unique().tolist()]]
        corr_yml_buff['references'] = list(set(combined_references))

        ## update TID
        combined_tid = []
        [combined_tid.extend(sublist) for sublist in [corr_tid.strip("[]").replace("'","").split(", ") for corr_tid in FILTERED_DF['tags.mitre_attack_id'].astype(str).dropna().unique().tolist()]]
        corr_yml_buff['tags']['mitre_attack_id'] = list(set(combined_tid))
        
        ### update search    
        corr_yml_buff['search'] =  str(updated_correlation_search + " | " + "`" + field_value_out_dict["correlation_yml_name"].lower().replace(" ", "_") + "_filter" + "`")

        ### update message
        corr_yml_buff['tags']['message'] = field_value_out_dict["correlation_yml_name"].lower() + " have been identified on $risk_object$."

        ### update description
        corr_yml_buff['description'] = field_value_out_dict["correlation_description"]
        
        self.hu.yml_dump_file(self.hu.get_cor_file_path(), corr_yml_buff)    

        return 
    
    def text_area_save_file(self)->None:
        yml_buff = st.session_state['yml_text_area']
        with open(self.hu.expand_path(self.hu.get_cor_file_path()), "w") as fw:
            fw.write(yml_buff)    
        return

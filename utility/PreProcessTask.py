"""
Python Script Name: PreProcessTask.py
Author: Teoderick Contreras
Date: 03-11.2025
version: 0.1
Description:
This module of the scout-helper Python tool facilitates pre-configure correlation searches based on Splunk Security Content:
 - Analytic Story
 - Mitre Att&ck Technique ID
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

class PreProcessUtility:

    def __init__(self):
        self.curdir = os.getcwd()
        self.HOME_PATH = Path.home()
        self.hu = HelperUtility()
        self.json_df = self.hu.json_to_df(self.hu.get_generated_sec_con_json_path())
        self.perc_ = self.hu.read_config_settings('source_count_perc',"correlation")
        self.corr_template = self.hu.read_config_settings('correlation_template')
        return
    
    def pre_process_by_analytic_story(self)->None:
        

        self.pre_process_by_tag(self.json_df, "tags.analytic_story", self.perc_, self.corr_template)

        return
    

    def pre_process_by_mitre_attack_tid(self)->None:
        

        self.pre_process_by_tag(self.json_df, "tags.mitre_attack_id", self.perc_, self.corr_template)
        return
    
    def pre_process_by_tag(self, json_df, field_tag, perc_, corr_template):
        
        ## delete and create new folder for new generated list of correlation search by tag
        if field_tag == "tags.mitre_attack_id":
            self.hu.delete_create_dir(self.hu.get_correlation_output_path_by_tag())
        if field_tag == "tags.analytic_story":
            self.hu.delete_create_dir(self.hu.get_correlation_output_path_by_story())

        option_analytic_story = json_df[field_tag].explode().dropna().unique()
        option_analytic_story =  [str(value) for value in option_analytic_story if value is not None] 

        with st.expander(f"**:blue[List of {field_tag}]**"):
            st.dataframe(option_analytic_story)
        
        if (self.hu.check_empty_list(option_analytic_story)):
            for  story_ in option_analytic_story:
                FILTERED_DF = json_df
                temp_dict = {}
                temp_list = []
                temp_list.append(story_)
                temp_list = list(filter(lambda x: x is not None, temp_list))
                temp_dict[field_tag] = temp_list
                FILTERED_DF, option_analytic_story_ = self.hu.filter_data_frame(FILTERED_DF, temp_dict)

                count_val = self.hu.compute_threshold_score(len(FILTERED_DF), perc_)
                updated_correlation_search = self.generate_splunk_search_condition(str(count_val), corr_template, temp_dict)
                
                try:
                    self.generate_correlation_by_tag(story_, FILTERED_DF, updated_correlation_search, field_tag)
                except Exception as e:
                    st.error(f"error in processing {story_}, {e}")
                
                st.divider()

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
    

    def generate_correlation_by_tag(self, field_tag_value, FILTERED_DF, updated_correlation_search, field_tag)->None:
        correlation_yml_name_field = ""
        if field_tag == "tags.analytic_story":
            correlation_yml_name_field = f"Correlation Search for {field_tag_value}"
            
            ## create a correlation yml file
            output_dir_path = self.hu.get_correlation_output_path_by_story()
        
        elif field_tag == "tags.mitre_attack_id":
            
            ## create a correlation yml file
            output_dir_path = self.hu.get_correlation_output_path_by_tag()
            
            ## load the tid-name-description json file
            try:
                with open(self.hu.get_generate_attack_data_tid_descp_file_path(), "r") as json_fh:
                    tid_descp_json = json.load(json_fh)
                correlation_yml_name_field = f"Correlation Search for {field_tag_value}-{tid_descp_json[field_tag_value][0]}"
                
            except FileNotFoundError:
                st.error(f"Error: File '{self.hu.get_generate_attack_data_tid_descp_file_path()}' not found.")
            except json.JSONDecodeError as e:
                st.error(f"Error decoding JSON: {e}")
            except Exception as e:
                st.error(f"An error occurred: {e}")

        ## copy the template file to a new correlation search file
        src_file_path = self.hu.get_correlation_yml_template_file_path()
        corr_yml_file_name = correlation_yml_name_field
        dst_file_path = os.path.join(output_dir_path, corr_yml_file_name.lower().replace(" ", "_").replace("-", "_").replace("/","_") + ".yml")

        try:
            shutil.copy(src_file_path, dst_file_path)
            
        except FileNotFoundError:
            st.error("Error: Source file not found.")
        except shutil.SameFileError:
            st.error("Error: Source and destination files are the same.")
        except PermissionError:
            st.error("Error: Permission denied.")
        except Exception as e:
            st.error(f"An error occurred: {e}")



        if field_tag == "tags.analytic_story":
            self.fill_up_correlation_yml_file_by_story(self.hu.expand_path(dst_file_path), corr_yml_file_name, FILTERED_DF, field_tag_value, updated_correlation_search)
        elif field_tag == "tags.mitre_attack_id":
            self.fill_up_correlation_yml_file_by_tid(self.hu.expand_path(dst_file_path), corr_yml_file_name, FILTERED_DF, field_tag_value, updated_correlation_search)
        return

    def fill_up_correlation_yml_file_by_story(self, correlation_yml_file_path, corr_yml_file_name, FILTERED_DF, field_tag_value, updated_correlation_search)->None:
        
        ## load the template yaml file
        with open(correlation_yml_file_path, "r") as f:
            corr_yml_file_buff = yaml.safe_load(f)

        ## load the analytic story description json file
        with open(self.hu.get_story_descp_file_path(), "r") as json_fh:
            story_descp_json = json.load(json_fh)
        
        if field_tag_value.lower() not in story_descp_json:
            st.error(f"ERROR: {field_tag_value} not found in story_descp_json")

        ## fill up the yaml file
        
        corr_yml_file_buff['name'] = corr_yml_file_name
        corr_yml_file_buff['author'] = self.hu.read_config_settings('default_author')
        corr_yml_file_buff['id'] = str(uuid.uuid4())
        corr_yml_file_buff['date'] = date.today().strftime('%Y-%m-%d')
        corr_yml_file_buff['tags']['analytic_story'] = field_tag_value
        corr_yml_file_buff['references']= story_descp_json[field_tag_value.lower()][1]
        corr_yml_file_buff['tags']['message'] = corr_yml_file_name.lower() + " have been identified on $risk_object$."

        ## update TID
        combined_tid = []
        [combined_tid.extend(sublist) for sublist in [corr_tid.strip("[]").replace("'","").split(", ") for corr_tid in FILTERED_DF['tags.mitre_attack_id'].astype(str).dropna().unique().tolist()]]

        corr_yml_file_buff['tags']['mitre_attack_id'] = list(set([i for i in combined_tid if i != "None"]))

        ## update search
        corr_yml_file_buff['search'] = str(updated_correlation_search + " | " + "`" + field_tag_value.lower().replace(" ", "_") + "_filter" + "`")
        
        ## update description
        init_description = f"The following correlation search identifies analytics related to {field_tag_value.lower()}. " + story_descp_json[field_tag_value.lower()][0]
        corr_yml_file_buff['description'] = init_description

        ### show the generated yml file
        self.hu.yml_dump_file(correlation_yml_file_path, corr_yml_file_buff)
        
        with st.expander(f"**:blue[{corr_yml_file_name}]**"):
            with open (correlation_yml_file_path, "r") as f:
                updated_corr_yml_buff = f.read()
            
            st.code(updated_corr_yml_buff, language="yaml", line_numbers= True)

        return
    

    def fill_up_correlation_yml_file_by_tid(self, correlation_yml_file_path, corr_yml_file_name, FILTERED_DF, field_tag_value, updated_correlation_search)->None:
        
        ## load the template yaml file
        with open(correlation_yml_file_path, "r") as f:
            corr_yml_file_buff = yaml.safe_load(f)

        ## load the tid-name-description json file
        with open(self.hu.get_generate_attack_data_tid_descp_file_path(), "r") as json_fh:
            tid_descp_json = json.load(json_fh)
        
        if field_tag_value not in tid_descp_json:
            st.error(f"{field_tag_value} not found in tid_descp_json")

        ## fill up the yaml file
        corr_yml_file_buff['name'] = corr_yml_file_name
        corr_yml_file_buff['author'] = self.hu.read_config_settings('default_author')
        corr_yml_file_buff['id'] = str(uuid.uuid4())
        corr_yml_file_buff['date'] = date.today().strftime('%Y-%m-%d')
        corr_yml_file_buff['tags']['mitre_attack_id'] = field_tag_value
        corr_yml_file_buff['references']= tid_descp_json[field_tag_value][2]        
        corr_yml_file_buff['tags']['message'] = corr_yml_file_name.lower() + " have been identified on $risk_object$."

        ## update search
        corr_yml_file_buff['search'] = str(updated_correlation_search + " | " + "`" + field_tag_value.lower().replace(" ", "_") + "_filter" + "`")

        ## update description
        init_description = f"The following correlation search identifies analytics related to {field_tag_value} - {tid_descp_json[field_tag_value][0]}. " + tid_descp_json[field_tag_value][1] 
        corr_yml_file_buff['description'] = init_description

        ## update analytic story
        combined_story = []
        [combined_story.extend(sublist) for sublist in [corr_tid.strip("[]").replace("'","").split(", ") for corr_tid in FILTERED_DF['tags.analytic_story'].astype(str).dropna().unique().tolist()]]
        corr_yml_file_buff['tags']['analytic_story'] = list(set([i for i in combined_story if i != "None"]))

        ### show the generated yml file
        self.hu.yml_dump_file(correlation_yml_file_path, corr_yml_file_buff)
        with st.expander(f"**:blue[{corr_yml_file_name}]**"):
            with open (correlation_yml_file_path, "r") as f:
                updated_corr_yml_buff = f.read()
            
            st.code(updated_corr_yml_buff, language="yaml", line_numbers= True)
        return
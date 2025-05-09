"""
Python Script Name: GenerateDataTask.py
Author: Teoderick Contreras, Splunk Threat Research Team (STRT)
Date: 03-11.2025
version: 0.1
Description:
This module of the scout-helper Python tool facilitates dataframe generation for all Splunk Security Content detections, 
enabling efficient data filtering and streamlined searches.
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
from attackcti import attack_client
from collections import defaultdict

from utility.UtilityHelper import HelperUtility

class GenerateDataUtility:

    def __init__(self):
        self.curdir = os.getcwd()
        self.hu = HelperUtility()


        return

    def generate_data(self)->None:

        ### get security content detection dir path
        security_content_path = self.hu.read_config_settings('security_content_detection_dir_path')
        security_content_base_path, detection_types, files = self.hu.enumerate_folder_path(security_content_path)
        if "deprecated" in detection_types:
            detection_types.remove("deprecated")
        ### prepare all possible detection set
        option_detection_type = st.multiselect("select detection type filter: ", detection_types)

        click = st.button("Generate", type="primary")

        if not option_detection_type:
            st.warning("Please select at least one detection type.")

        if click and option_detection_type:
            self.generate_json_data(option_detection_type, detection_types)
            self.generate_story_description_json()
            self.get_attack_data()


        return
    
    def get_encoding_type(self, file_path:str)->str:
        with open(file_path, 'rb') as f:
            result = chardet.detect(f.read())
            encoding = result['encoding']
        return encoding
    
    def read_yml_file(self, yml_file_path:str, encoding:str)->str:
        with open(yml_file_path, "r", encoding=encoding) as f:
            yml_buff = yaml.safe_load(f)

        return yml_buff
    
    def create_dataframe_from_json(self, data_list: list):
        if not isinstance(data_list, list):
            st.error("Expected a list of dictionaries but got:", type(data_list))
            return pd.DataFrame()
        
        ## this code is for deprecated data that cause some exception due to malform json file
        data_list = [data for data in data_list if isinstance(data, dict) and data not in (None, {}, [])]
        # Step 1: Normalize the JSON into a base DataFrame
        try:
            base_df = pd.concat([pd.json_normalize(data) for data in data_list], ignore_index=True)
        except Exception as e:
            raise ValueError(f"Failed to normalize JSON data: {e}")
        
        # Step 2: Explode and normalize specific fields
        fields_to_explode = ['rba.risk_objects', 'rba.threat_objects']
        consolidated_data = []

        for field in fields_to_explode:
            if field in base_df.columns:
                # Explode the field
                exploded_df = base_df[['id', field]].explode(field)
                
                # Handle cases where the field value is None or empty
                exploded_df = exploded_df[exploded_df[field].notna()]
                
                # Normalize the exploded dictionaries
                exploded_cols = pd.json_normalize(exploded_df[field])
                exploded_cols.columns = [f"{field}.{col}" for col in exploded_cols.columns]
                
                # Combine back into a single list grouped by `id`
                exploded_df = exploded_df.drop(columns=[field]).join(exploded_cols)
                grouped = exploded_df.groupby('id').agg(list).reset_index()
                consolidated_data.append(grouped)
        
        # Merge all consolidated data back to the base DataFrame
        for consolidated_df in consolidated_data:
            base_df = base_df.merge(consolidated_df, on='id', how='left')

        return base_df
    
    def generate_json_data(self, option_detection_type:str, detection_types:str)->None:
        # data_gen_list = []
        main_df =pd.DataFrame()
        for dt in option_detection_type:
            temp_list = []

            ### reset the detection_type_path variable
            detection_type_path = ""

            detection_type_path = os.path.join(self.hu.read_config_settings("security_content_detection_dir_path"), dt)

            dirs, subdirs, detection_files = self.hu.enumerate_folder_path(detection_type_path)

            with st.spinner(f"Generating {dt} Data Frame..."):
                for detection_file_name in detection_files:
                    detection_file_path = self.hu.expand_path(os.path.join(detection_type_path, detection_file_name))

                    ### check the encoding type
                    encoding = self.get_encoding_type(detection_file_path)

                    ### read detection yml file
                    yml_buff = self.read_yml_file(detection_file_path, encoding)

                    ### append to tmp list to check if there is data
                    temp_list.append(yml_buff)

                if temp_list:
                    

                    ### temporary dataframe for each dataclass
                    temp_df = self.create_dataframe_from_json(temp_list)

                    temp_df = self.add_detection_class_in_df(temp_df, dt)

                    temp_df = self.normalized_problematic_field_astype(temp_df)

                    ### concat tmp_df to the main_df of security content
                    main_df = pd.concat([main_df, temp_df], ignore_index=True)


                    with st.expander(f"{dt}: Detection Count: {len(detection_files)}"):
                        st.dataframe(temp_df)
                        st.write(temp_list)
                else:
                    pass

        ### save the big list to a json file
        main_df.to_json(self.hu.get_generated_sec_con_json_path(), orient="records")

        st.success(f"{self.hu.read_config_settings('generated_sec_con_json')} was successfully generated!", icon="✅")
        rows, cols = main_df.shape
        with st.expander(f"{self.hu.read_config_settings('generated_sec_con_json')}: Total Detection Count: {rows}"):
            st.dataframe(main_df)

        return
    
    def add_detection_class_in_df(self, df, detection_class_name:str):
        #df["DetectionClass"] = detection_class_name
        if "DetectionClass" not in df.columns:
            df["DetectionClass"] = None  # Initialize with None
        # Only update rows where 'DetectionClass' is NaN or empty
        df.loc[df["DetectionClass"].isna(), "DetectionClass"] = detection_class_name
        return df
    
    def normalized_problematic_field_astype(self, df):
        if 'tags.observable' in df:
            df['tags.observable'] = df['tags.observable'].astype(str)
        if "tests" in df:
            df['tests'] = df['tests'].astype(str)
        return df
    
    def dump_json_to_file(self, json_file_path:str, json_data:dict)->None:
        with open(json_file_path, "w") as json_fh:
            json.dump(json_data, json_fh, indent=4)
        
        return
    
    def generate_story_description_json(self)->None:
        with st.spinner("generating attack_data in progress. Please wait!!"):
            story_descp_dict = {}

            for dirs, subdirs, files in os.walk(self.hu.expand_path(self.hu.read_config_settings("security_content_story_dir_path"))):

                for file_ in files:
                    if not file_.endswith((".yaml",".yml")):
                        continue
                
                    story_file_path = os.path.join(dirs, file_)

                    encoding = self.get_encoding_type(story_file_path)

                    story_yml_buff = self.read_yml_file(story_file_path, encoding)

                    if story_yml_buff is not None and "name" in story_yml_buff:
                        _analytic_story = story_yml_buff['name'].lower()
                        ### save the needed fields from detection yml file
                        analytic_story_lower = story_yml_buff['name'].lower()
                        analytic_story_descp = story_yml_buff['description']
                        analytic_story_ref = story_yml_buff['references']
                    else:
                        _analytic_story = None
                        analytic_story_lower = ""
                        analytic_story_descp = ""
                        analytic_story_ref = ""
                    

                    if _analytic_story not in story_descp_dict:
                        story_descp_dict[_analytic_story] = [analytic_story_descp, analytic_story_ref]
                    if analytic_story_lower not in story_descp_dict:
                        story_descp_dict[analytic_story_lower] = [analytic_story_descp, analytic_story_ref]

                    
                    if analytic_story_lower != _analytic_story:
                        st.error(f"ERROR:{file_}, name:{analytic_story_lower}, story:{_analytic_story}")

            self.dump_json_to_file(self.hu.expand_path(self.hu.get_story_descp_file_path()), story_descp_dict)

            json_data = json.dumps(story_descp_dict, indent=4)
            st.success('{} was successfully generated!!!\n'.format(self.hu.read_config_settings("analytic_story_description_json_file_name")), icon="✅")
            with st.expander(self.hu.read_config_settings("analytic_story_description_json_file_name")):
                st.json(json_data)
                

        return
    

    def get_attack_data(self)->None:
        with st.spinner("generating attack_data in progress. Please wait!!"):
            try:
                attack = attack_client()
            except:
                st.warning("Attack CTI might be down.. working with cloned cti local repo...(https://github.com/mitre/cti )",icon="🏗️")
                
                ### lets do offline cti parsing
                attack = attack_client(local_paths = self.hu.expand_path(self.hu.read_config_settings("attackcti_repo_dir_path")))

            techniques = attack.get_techniques()
            attack_data_dict = defaultdict(list)
            attack_tid_dict = {}
            for technique in techniques:
                technique_id = technique['external_references'][0]['external_id']
                attack_data_dict[technique_id].append(technique['kill_chain_phases'][0]['phase_name'])
                attack_data_dict[technique_id].append(technique['name'])
                attack_tid_dict[technique_id] = [technique['name'], technique['description'], technique['external_references'][0]['url']]

            ### dump attack_data_dict to a json file 
            self.dump_json_to_file(self.hu.get_generated_attack_data_json_path(), attack_data_dict)
            json_data = json.dumps(attack_data_dict, indent=4)

            ### show the json file
            st.success('{} was successfully generated!!!\n'.format(self.hu.read_config_settings("generated_attack_data_json")), icon="✅")
            with st.expander(self.hu.read_config_settings("generated_attack_data_json")):
                st.json(json_data)

            ### dump attack_data_dict to a json file
            self.dump_json_to_file(self.hu.get_generate_attack_data_tid_descp_file_path(), attack_tid_dict)
            json_data = json.dumps(attack_tid_dict, indent=4)

            ### show the json file
            st.success('{} was successfully generated!!!\n'.format(self.hu.read_config_settings("generated_attack_tid_desc_json")), icon="✅")
            with st.expander(self.hu.read_config_settings("generated_attack_tid_desc_json")):
                st.json(json_data)
                
        return

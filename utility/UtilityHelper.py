"""
Python Script Name: UtilityHelper.py
Author: Teoderick Contreras
Date: 03-11.2025
version: 0.1
Description:
This module of the scout-helper Python tool provides utility functions 
to support various tasks across different scout-helper modules, ensuring efficient and reusable functionality.
"""
import streamlit as st
import yaml
import json
import pandas as pd
from PIL import Image
from pathlib import Path
import os
import sys
import shutil
from attackcti import attack_client
from collections import defaultdict
import chardet
from streamlit_extras.badges import badge

class HelperUtility:

    def __init__(self):
        self.curdir = os.getcwd()
        self.HOME_PATH = Path.home()
        self.data_dir_path = os.path.join(self.curdir, "data")
        self.cache_dir_path = os.path.join(self.curdir, "cache")
        self.template_dir_path = os.path.join(self.curdir, "template")
        self.output_dir_path = os.path.join(self.curdir, "output")
        self.config_file_path = os.path.join(self.curdir, "configuration/config.yaml")
        self.config_banner_img_file_path = os.path.join(self.curdir, "assets/banner.png")
        
        self.generated_sec_con_json_path = os.path.join(self.data_dir_path, self.read_config_settings('generated_sec_con_json'))
        self.generated_attack_data_json_path = os.path.join(self.data_dir_path,self.read_config_settings('generated_attack_data_json'))
        self.generated_security_content_json = os.path.join(self.data_dir_path, self.read_config_settings("generated_sec_con_json"))
        self.story_descp_file_path = os.path.join(self.data_dir_path, self.read_config_settings("analytic_story_description_json_file_name"))
        self.generate_attack_data_tid_descp_file_path = os.path.join(self.data_dir_path, self.read_config_settings("generated_attack_tid_desc_json"))
        self.generated_cache_sec_con_filter_path = os.path.join(self.cache_dir_path, self.read_config_settings('cache_sec_con_filter_name'))
        
        self.correlation_yml_template_file_path = os.path.join(self.template_dir_path, self.read_config_settings('correlation_yml_template_file_path',"correlation"))
        
        self.correlation_output_dir_path = os.path.join(self.output_dir_path, self.read_config_settings('correlation_output_dir',"correlation"))
        self.correlation_output_path_by_tag = os.path.join(self.output_dir_path, self.read_config_settings('correlation_output_dir_by_tag',"correlation"))
        self.correlation_output_path_by_story = os.path.join(self.output_dir_path, self.read_config_settings('correlation_output_dir_by_story',"correlation"))
        
        correlation_file_name = self.read_config_settings('correlation_yml_name',"correlation").lower().replace(" ", "_") + ".yml"
        self.cor_file_path = os.path.join( self.output_dir_path, correlation_file_name)
        self.chosen_cor_yml_file = ""
        return
    
    ######################################################################
    #### file and dir path get functions
    ######################################################################

    def get_config_file_path(self)->str:
        return self.config_file_path 

    def get_config_banner_img_file_path(self)->str:
        return self.config_banner_img_file_path 
    
    def get_correlation_output_path(self)->str:
        return os.path.join(self.curdir, self.read_config_settings("correlation_output_dir"))
    
    def get_generated_sec_con_json_path(self)->str:
        return self.generated_sec_con_json_path
    
    def get_story_descp_file_path(self)->str:
        return self.story_descp_file_path

    def get_generated_attack_data_json_path(self)->str:
        return self.generated_attack_data_json_path
    
    def get_generate_attack_data_tid_descp_file_path(self)->str:
        return self.generate_attack_data_tid_descp_file_path
    
    def get_correlation_yml_template_file_path(self)->str:
        return self.correlation_yml_template_file_path
    
    def get_correlation_output_dir_path(self)->str:
        return self.correlation_output_dir_path
    
    def get_correlation_output_path_by_tag(self)->str:
        return self.correlation_output_path_by_tag

    def get_correlation_output_path_by_story(self)->str:
        return self.correlation_output_path_by_story
    
    def get_cor_file_path(self):
        return self.cor_file_path
    
    ######################################################################
    #### config processing
    ######################################################################
    def load_config(self)->str:
        with open(self.get_config_file_path(), "r") as file:
            return yaml.safe_load(file)
        
    def read_config_settings(self, setting_field:str, key_tag="settings")->str:
        cfg = self.load_config()
        config_field = cfg[key_tag][setting_field]
        return config_field

    def update_config(self, config:yaml)->None:
        with open(self.get_config_file_path(), "w") as file:
            yaml.dump(config, file, default_flow_style=False)

        return

    def write_config_settings(self, tag: str, value, key_tag="settings") -> yaml:
        cfg = self.load_config()

        # Automatically convert from string to list if necessary
        if isinstance(cfg[key_tag].get(tag), list) and isinstance(value, str):
            try:
                value = yaml.safe_load(value)  # Convert stringfield list to a real list
            except yaml.YAMLError:
                st.error(yaml.YAMLError)
                pass  # If conversion fails, keep it as a string
        
        
        cfg[key_tag][tag] = value  # Store properly as list or string

        self.update_config(cfg)
        return cfg

    def get_config_text_input(self, field_name:str, session_state, key_tag="settings", help_str="")->str:
        text_input_init = self.read_config_settings(field_name, key_tag)
        normalize_field_name = field_name.replace("_"," ")
        text_input_value = st.text_input(f":blue[**{normalize_field_name}:**]",value = text_input_init,disabled=session_state, help=help_str)
        return text_input_value 

    def update_config_field(self, field_name:str, field_value, session_state, key_tag="settings")->None:

        if field_value == "":
            st.error(f"please specify value for : {field_name}")
        else:
            self.write_config_settings(field_name, field_value, key_tag)
        return

    def wrapper_get_update_config_field(self, field_name:str, session_state, key_tag="settings", help_str="")->None:
        config_field_value = self.get_config_text_input(field_name, session_state, key_tag, help_str)
        self.update_config_field(field_name, config_field_value, session_state, key_tag)
        return

    def get_config_code_value(self, field_name:str, session_state, code_language:str)->str:
        code_init = self.read_config_settings(field_name)
        normalized_field_name = field_name.replace("_"," ")
        st.markdown(f":blue[**{normalized_field_name}:**]")
        newline_code_init = code_init.replace(", ", ", \n").replace(" by", "\n by").replace("| ", "\n| ")
        code_value = st.code(newline_code_init, language=code_language)
        return code_value
    
    
    ######################################################################
    ### banner functions
    ######################################################################
    def render_image(self, image_file_path:str, caption_note:str="", width: int = 300, )-> None:
        img = Image.open(image_file_path)
        st.image(img, caption=caption_note, use_container_width=True)
        return
    
    def show_banner(self)->None:

        st.title("**:orange[S.C.O.U.T Helper:]**")
        #self.render_image(self.get_config_banner_img_file_path())
        st.header(":orange[S]plunk :orange[C]orrelation :orange[O]utput & :orange[U]tility :orange[T]ool :orange[Helper] ")
        st.divider()
        with st.sidebar:
            self.render_image(self.get_config_banner_img_file_path(), "Br3akp0int")

            
            st.divider()
            st.write("**:orange[Splunk Detection Development Tools:]**")
            col1, col2 = st.columns(2)
            
            with col1:
                st.write(":blue[Attack Range:]")
                st.write(":blue[Security Content:]")
                st.write(":blue[Attack Data:]")
                st.write(":blue[contentctl:]")
                st.write(":blue[scout-helper:]")
            with col2:
                badge(type="github", url="https://github.com/splunk/attack_range", name="splunk/attack_range")
                badge(type="github", url="https://github.com/splunk/security_content", name="splunk/security_content")
                badge(type="github", url="https://github.com/splunk/attack_data", name="splunk/attack_data")
                badge(type="github", url="https://github.com/splunk/contentctl", name="splunk/contentctl")
                badge(type="github", url="https://github.com/splunk/scout-helper", name="splunk/scout-helper")

            st.divider()
        return
    
    ######################################################################
    ### generate data
    ######################################################################

    def enumerate_folder_path(self, folder_path:str)->tuple:
        for dirs, subdirs, macro_list in os.walk(self.expand_path(folder_path)):
            return dirs, subdirs, macro_list

    def expand_path(self, file_path:str)->str:
        if "~" in file_path:
            return str(file_path).replace("~", str(self.HOME_PATH))
        else:
            return file_path
        
    ######################################################################
    ### correlation data
    ######################################################################
    
    def json_to_df(self, json_file_path):
        df= None
        if os.path.isfile(json_file_path):
            df = pd.read_json(json_file_path)
        return df
    
    def dataframe_column_to_list(self, df):
        if df is not None:
            return df.columns.tolist()
        else:
            st.error("df is None, cannot access columns.")
    
    def generate_config_input_box(self, config, text_input_label:str, config_field_name:str, field_value_out_dict:dict, key_tag = "settings")->None:

        #config_field_value = config[key_tag][config_field_name]

        config_field_value = self.read_config_settings(config_field_name, key_tag)
        input_box_value = st.text_input(f":blue[**{text_input_label}:**]",value = config_field_value, key = config_field_name)
        self.update_config_field(config_field_name, input_box_value, st.session_state.disabled, key_tag)
        field_value_out_dict[config_field_name] = input_box_value
        return
    
    def filter_data_frame(self, FILTERED_DF, tag_dict:dict):

        for field_name, field_value in tag_dict.items():
                if (self.check_empty_list(field_value)):
                    #st.success("Filtered by {}: {}".format(field_name, field_value),icon="✅")
                    FILTERED_DF = self.filter_via_substring(field_value, field_name, FILTERED_DF)
                    tag_dict[field_name] = field_value
        return FILTERED_DF, tag_dict
    
    def check_empty_list(self, target_list:list)->bool:
        if len(target_list) == 0 or (len(target_list) == 1 and target_list[0] == ""):
            return False
        else:
            return True 
        
    def filter_via_substring(self, option_list:list, column_name:str, FILTERED_DF):
        #st.write(option_list)
        FILTERED_DF_ = FILTERED_DF
        FILTERED_DF_BUFF = pd.DataFrame()
        temp_list = []
        FILTERED_DF = self.convert_df_column_name_to_str(column_name, FILTERED_DF)
        
        with st.expander(f"**:blue[Filtered Dataframe by {column_name} : {option_list}]**"):
            for option_val in option_list:
                FILTERED_DF_BUFF_PER_SUBSTR = pd.DataFrame()
                FILTERED_DF_BUFF, FILTERED_DF_BUFF_PER_SUBSTR = self.find_sub_str_in_df_column_name(column_name, FILTERED_DF_BUFF, FILTERED_DF, option_val)

                if FILTERED_DF_BUFF.empty:
                    st.error("filtered data frame is empty")
                else:

                    expander_name = "Filtered DataFrame by: " + option_val

                    
                    st.write(f":orange[{expander_name}]")
                    
                    self.count_detection_type(FILTERED_DF_BUFF_PER_SUBSTR)
                    st.dataframe(FILTERED_DF_BUFF_PER_SUBSTR,width=1000, height=600)
                    st.divider()

        return FILTERED_DF_BUFF
    
    def convert_df_column_name_to_str(self, column_name:str, df):
        df[column_name] = df[column_name].astype(str)

        return df
    
    def find_sub_str_in_df_column_name(self, column_name:str, FILTERED_DF_BUFF, FILTERED_DF, option_val:str):
        FILTERED_DF_BUFF_PER_SUBSTR = pd.DataFrame()
        FILTERED_DF_ = FILTERED_DF[FILTERED_DF[column_name].str.contains(str(option_val), case=False)]
        FILTERED_DF_BUFF = pd.concat([FILTERED_DF_BUFF, FILTERED_DF_], ignore_index=True)
        FILTERED_DF_BUFF = FILTERED_DF_BUFF.drop_duplicates(subset= ['name'])
        FILTERED_DF_BUFF_PER_SUBSTR = pd.concat([FILTERED_DF_BUFF_PER_SUBSTR, FILTERED_DF_], ignore_index=True)
        return FILTERED_DF_BUFF, FILTERED_DF_BUFF_PER_SUBSTR
    
    def count_detection_type(self, FILTERED_DF):
        # Count the occurrences of each type
        counts = FILTERED_DF['type'].value_counts()
        
        # Create a DataFrame with the counts and ensure all necessary columns exist
        counts_df = pd.DataFrame({"Count: ": counts.values}, index=counts.index)

        # Ensure the required columns exist
        for category in ['TTP', 'Anomaly', 'Hunting', 'Correlation']:
            if category not in counts_df.index:
                counts_df.loc[category] = [0]  # Add the missing category with a count of 0
        
        # Add a total detection count
        counts_df = counts_df.transpose()
        counts_df['Total Detection Count'] = counts_df[['TTP', 'Anomaly', 'Hunting', 'Correlation']].sum(axis=1)
        
        # Reset the index to include "Category" as a column (optional for charting or display)
        counts_df = counts_df.rename_axis("Category").reset_index()
        
        # Display the DataFrame in Streamlit
        st.dataframe(counts_df, use_container_width=True)
        
        return counts_df
    
    def merge_dicts(self, dict1:dict, dict2:dict)->dict:
        dict_concatenated = {}
        for key in set(dict1.keys()).union(dict2.keys()):
            if key in dict1 and key in dict2:
                dict_concatenated[key] = dict1[key] + dict2[key]
            elif key in dict1:
                dict_concatenated[key] = dict1[key]
            else:
                dict_concatenated[key] = dict2[key]

        return dict_concatenated
        
    def yml_dump_file(self, yml_file_name, data_to_write):
        with open(self.expand_path(yml_file_name), "w") as fw:
            yaml.dump(data_to_write, fw, default_flow_style=False, sort_keys=False)
        return
    
    ######################################################################
    ### pre process data
    ######################################################################
    def delete_create_dir(self, folder_path:str)->None:
        if os.path.exists(folder_path):
            shutil.rmtree(folder_path)
        os.makedirs(folder_path)
        return

    def compute_threshold_score(self, total_score:int, threshold:float)->int:
        threshold_score = round(total_score * float(threshold))
        if total_score <= 2 or threshold_score <= 2:
            threshold_score = 2
        return threshold_score
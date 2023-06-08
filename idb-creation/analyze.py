from scatter import run_scatterload
from find_dbgsym import init_dbt
from analyze_data_struct import init_functions, init_strings

def analyze():
    # Initialize segments and scatterloads
    run_scatterload()

    # Initialize debug table information
    init_dbt()

    # Initialize functions and strings
    init_functions()
    init_strings()

if __name__ == "__main__":
    analyze()
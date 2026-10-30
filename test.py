from metadata_engine import extract_metadata

file_path = input("Enter file path: ")

try:
    results = extract_metadata(file_path)

    print("\n===== METATRACE RESULTS =====")

    for key, value in results.items():
        print(f"{key}: {value}")

except Exception as error:
    print("Error:", error)
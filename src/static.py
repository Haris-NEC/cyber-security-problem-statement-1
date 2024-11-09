import os
import json
import array
import math
import pefile
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from PyPDF2 import PdfReader, PdfWriter

# For calculating the entropy
def get_entropy(data):
    if len(data) == 0:
        return 0.0
    occurrences = array.array('L', [0] * 256)
    for x in data:
        occurrences[x if isinstance(x, int) else ord(x)] += 1

    entropy = 0
    for x in occurrences:
        if x:
            p_x = float(x) / len(data)
            entropy -= p_x * math.log(p_x, 2)
    return entropy

# For extracting the resources part
def get_resources(pe):
    resources = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        try:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                size = resource_lang.data.struct.Size
                                entropy = get_entropy(data)
                                resources.append([entropy, size])
        except Exception:
            return resources
    return resources

# Extracts information from the PE file
def extract_infos(fpath):
    pe = pefile.PE(fpath)
    res = {}
    res['Machine'] = pe.FILE_HEADER.Machine
    res['SectionsMeanEntropy'] = sum(x.get_entropy() for x in pe.sections) / len(pe.sections)

    resources = get_resources(pe)
    res['ResourcesMeanEntropy'] = sum(x[0] for x in resources) / len(resources) if resources else 0

    try:
        res['Imports'] = [imp.name.decode('utf-8') if isinstance(imp.name, bytes) else imp.name
                          for entry in pe.DIRECTORY_ENTRY_IMPORT for imp in entry.imports]
    except AttributeError:
        res['Imports'] = []

    try:
        res['ExportsNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    except AttributeError:
        res['ExportsNb'] = 0
    return res

# Checks if the file is potentially malicious
def is_malicious(file_info):
    indicators = []

    if file_info['SectionsMeanEntropy'] > 7.5 or file_info['ResourcesMeanEntropy'] > 7.5:
        indicators.append("High entropy in sections/resources.")

    suspicious_imports = ['CreateProcess', 'VirtualAlloc', 'WriteProcessMemory', 'OpenProcess', 'TerminateProcess']
    if any(imp in file_info['Imports'] for imp in suspicious_imports):
        indicators.append("Suspicious API imports detected.")

    return "Potentially Malicious" if indicators else "No malicious indicators", indicators

# Outputs analysis in JSON format
def output_analysis(fpath, file_info, result):
    output_data = {
        "FileName": os.path.basename(fpath),
        "Status": result[0],
        "FileProperties": {k: v for k, v in file_info.items() if k != "Imports"},
        "Imports": file_info.get("Imports"),
        "Indicators": result[1]
    }
    json_result = json.dumps(output_data, indent=4)
    print(json_result)
    return json_result

# Simplified analysis function
def simple_analysis(fpath):
    print("\n--- SIMPLE ANALYSIS ---\n")
    file_info = extract_infos(fpath)
    result = is_malicious(file_info)

    # Display a simplified summary of the analysis
    print(f"File Name: {os.path.basename(fpath)}\n")
    print(f"Machine Type: {file_info['Machine']}")
    print(f"Sections Mean Entropy: {file_info['SectionsMeanEntropy']:.2f}")
    print(f"Resources Mean Entropy: {file_info['ResourcesMeanEntropy']:.2f}")
    print(f"Number of Exports: {file_info['ExportsNb']}")
    print(f"\nStatus: {result[0]}\n")

    if result[0] == "Potentially Malicious":
        print("The file is potentially malicious based on the analysis.\n")
        print("Indicators:")
        for indicator in result[1]:
            print(f"- {indicator}")
    else:
        print("No malicious indicators were found. The file appears safe.")

# Function to save analysis result and overlay it onto the existing PDF
def save_analysis_to_existing_pdf(fpath, file_info, result, existing_pdf_path):
    filename = os.path.basename(fpath)
    exe_name = os.path.splitext(filename)[0]

    overlay_pdf_filename = "overlay.pdf"
    c = canvas.Canvas(overlay_pdf_filename, pagesize=letter)
    width, height = letter

    text_x = 100
    text_y = height - 60
    line_height = 14

    c.setFont("Helvetica-Bold", 16)
    c.drawString(text_x, text_y, f"Full Analysis of {filename}")
    text_y -= 100

    c.setFont("Helvetica", 10)

    # Updated function to handle line wrapping for imports
    def write_text_lines(text_lines, current_y, is_imports=False):
        nonlocal c
        if is_imports:
            import_line = ""
            for imp in text_lines:
                if len(import_line) + len(imp) + 2 > 80:
                    c.drawString(text_x, current_y, import_line)
                    current_y -= line_height
                    import_line = imp
                    if current_y < 40:
                        c.showPage()
                        c.setFont("Helvetica", 10)
                        current_y = height - 40
                else:
                    import_line += (", " if import_line else "") + imp

            c.drawString(text_x, current_y, import_line)
            current_y -= line_height
            if current_y < 40:
                c.showPage()
                c.setFont("Helvetica", 10)
                current_y = height - 40
            return current_y

        for line in text_lines:
            c.drawString(text_x, current_y, line)
            current_y -= line_height
            if current_y < 40:
                c.showPage()
                c.setFont("Helvetica", 10)
                current_y = height - 40
        return current_y

    text_lines = [
        "----- File Information -----",
        f"File Name: {filename}",
        f"Machine Type: {file_info['Machine']}",
        f"Sections Mean Entropy: {file_info['SectionsMeanEntropy']:.2f}",
        f"Resources Mean Entropy: {file_info['ResourcesMeanEntropy']:.2f}",
        f"Number of Exports: {file_info['ExportsNb']}",
        "\n"
    ]
    text_y = write_text_lines(text_lines, text_y)

    # Print imports with line wrapping
    if file_info['Imports']:
        text_y = write_text_lines(file_info['Imports'], text_y, is_imports=True)
    else:
        text_y = write_text_lines(["No imports detected."], text_y)

    text_lines = ["----- Malicious Indicators -----", f"Status: {result[0]}"]
    if result[1]:
        text_lines.extend([f"- {indicator}" for indicator in result[1]])
    else:
        text_lines.append("No suspicious indicators found.")
    text_y = write_text_lines(text_lines, text_y)

    c.save()

    overlay_reader = PdfReader(overlay_pdf_filename)
    existing_reader = PdfReader(existing_pdf_path)
    writer = PdfWriter()

    for i, overlay_page in enumerate(overlay_reader.pages):
        if i < len(existing_reader.pages):
            existing_reader.pages[i].merge_page(overlay_page)
            writer.add_page(existing_reader.pages[i])
        else:
            writer.add_page(overlay_page)

    output_pdf_path = os.path.join(os.path.dirname(existing_pdf_path), f"{exe_name}_analysis_report.pdf")

    with open(output_pdf_path, 'wb') as output_pdf:
        writer.write(output_pdf)

    os.remove(overlay_pdf_filename)
    print(f"Analysis successfully saved as {output_pdf_path}.")

# Full analysis function
def full_analysis(fpath):
    print("\n--- FULL ANALYSIS ---\n")
    file_info = extract_infos(fpath)
    result = is_malicious(file_info)

    output_analysis(fpath, file_info, result)

    existing_pdf_path = "/home/kali/Downloads/MAT/report.pdf"
    save_analysis_to_existing_pdf(fpath, file_info, result, existing_pdf_path)

# Main menu function
def main_menu():
    print("Choose an option:")
    print("1. Simple Analysis (Summary)")
    print("2. Full Analysis (Detailed JSON Output and PDF)")
    user_choice = input("Enter your choice (1 or 2): ")

    file_path = input("Enter the file path: ")

    if user_choice == "1":
        simple_analysis(file_path)
    elif user_choice == "2":
        full_analysis(file_path)
    else:
        print("Invalid choice. Please enter 1 for Simple Analysis or 2 for Full Analysis.")

if __name__ == "__main__":
    main_menu()

from backend.scanner import analyze_website, calculate_privacy_score

url = input("Enter website URL: ")

result = analyze_website(url)

# DISPLAY SCAN RESULTS

for category, data in result.items():

    print("\n==========", category, "==========")

    if isinstance(data, dict):

        for name, value in data.items():

            print("\n", name)

            if isinstance(value, dict):

                for attribute, status in value.items():

                    print("   ", attribute, ":", status)

            else:

                print("   ", value)

    elif isinstance(data, list):

        if not data:
            print("No external resources detected.")

        for resource in data:
            print(resource)

    else:

        print(data)


# CALCULATE PRIVACY SCORE

score_result = calculate_privacy_score(result)

print("\n========== PRIVACY SCORE ==========")

if "Privacy Score" in score_result:

    print(
        "Overall Score:",
        score_result["Privacy Score"],
        "/100"
    )

    print("\nScore Breakdown:")

    for category, points in score_result["Breakdown"].items():

        print(category, ":", points)

else:

    print(score_result)

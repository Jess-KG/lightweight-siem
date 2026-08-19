 # if "Computer" in child.tag:
                #     print("Computer: ", child.text)
                # if "TimeCreated" in child.tag:
                #     print("Date: ", child.attrib['SystemTime'].split(' ')[0])
                #     print("Time: ", child.attrib['SystemTime'].split(' ')[1].split('.')[0])

                #print everuthing
                # I WANT TO PRINT EVERYTHING IN THAT ROOT
                print("found Event ID")


###PRINTING ALL XML
   #now print all the xml for this
                print("XML: ", ET.tostring(original_root, encoding="unicode"))
                print("--------------------------------------------------")
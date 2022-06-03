import click
import csv
import os
import shodan
from shodan.cli.helpers import get_api_key
import sys
from tabulate import tabulate


#configuration

api = shodan.Shodan(get_api_key())

#Lists and containers
headers = ['IP', 'CVE', 'CVSS', 'CVEs', 'High CVEs', 'Critical CVEs']
unikkeIPs = []
unikkeMaskiner = []
limiter = 5



#værktøjer
def clrscrn():
    click.clear()


#START

#clear screen
clrscrn()

#Menu

print('')
print('Velkommen til Vuln + CVE + CVSS Grabber rettet mod Shodan.io')
print('')
print('')
print('Velkommen til Saarbarheds fangeren. Indtast en organisations navn herunder for at begynde skanningen.')
print('(Eks: TDC, Stofa, Telenor, ~)')
print('')
userInput = input('Indtast: ')

#print resultater
try:
    results = api.search(f'org:{userInput} has_vuln:true', limit=limiter)

    #Error handler ved 0 resultater

    if results['total'] == 0:
        print('Fundne resultater {}'.format(results['total']))
        print('')
        print('Din sogning gav ingen resultater, enten er der sket en fejl eller ogsaa er der ikke nogen på din sogning.')
        print('')
        
        input('Tryk enter for at lukke programmet...')
        clrscrn()
        exit()
    
    #Resultat behandling

    print('Fundne resultater {}'.format(results['total']))
    print('')
    print('Vaelg venligst en af folgende muligheder')
    print('1: Vis den indhentede data i konsollen.')
    print('2: Skriv den indhentede data til en csv fil.')
    print('3: Lav en anden sogning.')
    print('4: Afslutte programmet')

    option = int(input('Option: '))

    if option == 1:
        
        #print data til konsol med tabeller

        for result in results['matches']:
            
            numberOfCVEs = 0
            numberOfHighCVEs = 0
            numberOfCriticalCVEs = 0

            nameCVE = []

            table = []

            for item in result['vulns']:
                
                numberOfCVEs = numberOfCVEs + 1
                cvssScore = float(result['vulns'][item]['cvss'])
                nameCVE.append(item)
                    
                # Check how critical the CVSS is
                    
                if (cvssScore >= 9.0):
                    
                    numberOfCriticalCVEs = numberOfCriticalCVEs + 1
                        
                elif (9.0 > cvssScore >= 7.0):
                    
                    numberOfHighCVEs = numberOfHighCVEs + 1
                        
                table.append([result['ip_str'], nameCVE, cvssScore, numberOfCVEs, numberOfHighCVEs, numberOfCriticalCVEs])
            
            print(tabulate(table, headers=headers, tablefmt='fancy_grid'))

            print('')
            print('Vil du gerne:')
            print('1) Skrive dataen til en CSV fil')
            print('2) Prove en anden search query')
            option = int(input('Option: '))
            
            if option == 1:
            
                # gem data til en CSV fil
        
                with open('shodan-data.csv', 'w', encoding='UTF8', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(headers)
                    
                    for result in results['matches']:
                        
                        numberOfCVEs = 0
                        numberOfHighCVEs = 0
                        numberOfCriticalCVEs = 0
                        
                        nameCVE = []
                        
                        for item in result['vulns']:
                        
                            numberOfCVEs = numberOfCVEs + 1
                            cvssScore = float(result['vulns'][item]['cvss'])
                            nameCVE.append(item)
                            
                            # Tjek hvor kritisk CVSS er
                            
                            if (cvssScore >= 9.0):
                            
                                numberOfCriticalCVEs = numberOfCriticalCVEs + 1
                                
                            elif (9.0 > cvssScore >= 7.0):
                            
                                numberOfHighCVEs = numberOfHighCVEs + 1
                                
                        rows = [result['ip_str'], nameCVE, cvssScore, numberOfCVEs, numberOfHighCVEs, numberOfCriticalCVEs]
                        writer.writerow(rows)
                        
                        print('En CSV fil med dataen er nu oprettet.')
                        print('')
                        input('Tryk enter for at lukke programmet...')
                        clrscrn()
                        exit()


            
            elif option == 2:
                print('')
                input('Tryk enter for at lukke programmet...')
                clrscrn()
                exit()     
            
    elif option == 2:
    
        # gem data til en CSV fil
        
        with open('shodan-data.csv', 'w', encoding='UTF8', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            
            for result in results['matches']:
                
                numberOfCVEs = 0
                numberOfHighCVEs = 0
                numberOfCriticalCVEs = 0
                
                nameCVE = []
                
                for item in result['vulns']:
                
                    numberOfCVEs = numberOfCVEs + 1
                    cvssScore = float(result['vulns'][item]['cvss'])
                    nameCVE.append(item)
                    
                    # Tjek hvor kritisk CVSS er
                    
                    if (cvssScore >= 9.0):
                    
                        numberOfCriticalCVEs = numberOfCriticalCVEs + 1
                        
                    elif (9.0 > cvssScore >= 7.0):
                    
                        numberOfHighCVEs = numberOfHighCVEs + 1
                        
                rows = [result['ip_str'], nameCVE, cvssScore, numberOfCVEs, numberOfHighCVEs, numberOfCriticalCVEs]
                writer.writerow(rows)
                
                print('En CSV fil med dataen er nu oprettet.')
                print('')
                input('Tryk enter for at lukke programmet...')
                clrscrn()
                exit()
                    
    elif option == 3:
    
        # clearvinduet og luk programmet
        
        clrscrn()
        exit()
    
    elif option ==4:

        #quit

        exit()
    
            
except (NameError, TypeError) as error:
    print(error)
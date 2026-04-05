# OpenSIEM - GPL-3.0 Licensed
# Copyright (c) 2024–present
# See LICENSE for details.

import os
import time

ascii_art = r"""
                                                                                                    
                                                                                                    
                                                                                                    
                                                                                                    
                                                                                                    
                                                                                                    
                                                                                                    
                                               @@@@@@                                               
                                              @@@@@@@@                                              
                                             @@@@  @@@@                                             
                                            @@@@    @@@@                                            
                                            @@@      @@@@                                           
                        @@@@@              @@@@       @@@              @@@@@                        
                      @@@@@@@@@@@          @@@        @@@          @@@@@@@@@@@                      
                      @@@    @@@@@@@@     @@@@        @@@@      @@@@@@@    @@@                      
                      @@@@       @@@@@@   @@@@        @@@@   @@@@@@@      @@@@                      
                       @@@@         @@@@@@@@@@         @@@@@@@@@@        @@@@                       
                        @@@@          @@@@@@@          @@@@@@@          @@@@@                       
                         @@@@           @@@@@@        @@@@@@            @@@@                        
                          @@@@           @@@@@@@    @@@@@@@           @@@@@                         
                           @@@@          @@@@@@@@@@@@@@ @@@          @@@@@                          
                            @@@@         @@@   @@@@@@   @@@@        @@@@                            
                             @@@@@      @@@@@@@@@@@@@@@@@@@@      @@@@@                             
                        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                        
                  @@@@@@@@@@@@@@@@@@@@@ @@@@@@@      @@@@@@@ @@@@@@@@@@@@@@@@@@@@@                  
               @@@@@@@@@@        @@@@@  @@@@@          @@@@@  @@@@@        @@@@@@@@@@               
             @@@@@                 @@@@@@@@@    @@@@    @@@@@@@@@                 @@@@@@            
            @@@@                    @@@@@@@@   @@@@@@   @@@@@@@@                    @@@@            
            @@@@@                  @@@@@@@@@   @@@@@@   @@@@@@@@@                  @@@@@            
              @@@@@@@@@           @@@@@ @@@@@          @@@@@  @@@@           @@@@@@@@@              
                 @@@@@@@@@@@@@@@@@@@@   @@@@@@@      @@@@@@@   @@@@@@@@@@@@@@@@@@@@                 
                      @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                      
                             @@@@@   @@@@@@@@@@@@@@@@@@@@@@@@@@@  @@@@@                             
                            @@@@         @@@   @@@@@@   @@@@        @@@@                            
                           @@@@          @@@@ @@@@@@@@@ @@@          @@@@                           
                          @@@@           @@@@@@@@  @@@@@@@@           @@@@                          
                         @@@@            @@@@@@      @@@@@@            @@@@                         
                        @@@@           @@@@@@          @@@@@@           @@@@                        
                       @@@@         @@@@@@@@@          @@@@@@@@@         @@@@                       
                      @@@@       @@@@@@@  @@@@        @@@@  @@@@@@@       @@@@                      
                      @@@     @@@@@@@     @@@@        @@@@     @@@@@@@     @@@                      
                      @@@@@@@@@@@@         @@@        @@@         @@@@@@@@@@@@                      
                       @@@@@@@             @@@        @@@             @@@@@@@                       
                                           @@@@      @@@@                                           
                                            @@@@    @@@@                                            
                                             @@@@   @@@@                                            
                                              @@@@@@@@@                                             
                                               @@@@@@                                               
                                                  @                                                 
                                                                                                    
                                                                                                    
                                                                                                    
                                                                                                    
                                                                                                    
"""

def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

# Animation loop
for i in range(20):  # Adjust the range for a longer or shorter animation
    clear_console()
    # Print leading blank lines for the slide down effect
    print("\n" * i, end="")
    print(ascii_art)
    time.sleep(0.1)  # Adjust the sleep time for speed of animation


print("                                                                                                                                                               ")
print("                                                                                                                                                               ")
print("     OOOOOOOOO                                                                  SSSSSSSSSSSSSSS IIIIIIIIIIEEEEEEEEEEEEEEEEEEEEEEMMMMMMMM               MMMMMMMM")
print("   OO:::::::::OO                                                              SS:::::::::::::::SI::::::::IE::::::::::::::::::::EM:::::::M             M:::::::M")
print(" OO:::::::::::::OO                                                           S:::::SSSSSS::::::SI::::::::IE::::::::::::::::::::EM::::::::M           M::::::::M")
print("O:::::::OOO:::::::O                                                          S:::::S     SSSSSSSII::::::IIEE::::::EEEEEEEEE::::EM:::::::::M         M:::::::::M")
print("O::::::O   O::::::Oppppp   ppppppppp       eeeeeeeeeeee    nnnn  nnnnnnnn    S:::::S              I::::I    E:::::E       EEEEEEM::::::::::M       M::::::::::M")
print("O:::::O     O:::::Op::::ppp:::::::::p    ee::::::::::::ee  n:::nn::::::::nn  S:::::S              I::::I    E:::::E             M:::::::::::M     M:::::::::::M")
print("O:::::O     O:::::Op:::::::::::::::::p  e::::::eeeee:::::een::::::::::::::nn  S::::SSSS           I::::I    E::::::EEEEEEEEEE   M:::::::M::::M   M::::M:::::::M")
print("O:::::O     O:::::Opp::::::ppppp::::::pe::::::e     e:::::enn:::::::::::::::n  SS::::::SSSSS      I::::I    E:::::::::::::::E   M::::::M M::::M M::::M M::::::M")
print("O:::::O     O:::::O p:::::p     p:::::pe:::::::eeeee::::::e  n:::::nnnn:::::n    SSS::::::::SS    I::::I    E:::::::::::::::E   M::::::M  M::::M::::M  M::::::M")
print("O:::::O     O:::::O p:::::p     p:::::pe:::::::::::::::::e   n::::n    n::::n       SSSSSS::::S   I::::I    E::::::EEEEEEEEEE   M::::::M   M:::::::M   M::::::M")
print("O:::::O     O:::::O p:::::p     p:::::pe::::::eeeeeeeeeee    n::::n    n::::n            S:::::S  I::::I    E:::::E             M::::::M    M:::::M    M::::::M")
print("O::::::O   O::::::O p:::::p    p::::::pe:::::::e             n::::n    n::::n            S:::::S  I::::I    E:::::E       EEEEEEM::::::M     MMMMM     M::::::M")
print("O:::::::OOO:::::::O p:::::ppppp:::::::pe::::::::e            n::::n    n::::nSSSSSSS     S:::::SII::::::IIEE::::::EEEEEEEE:::::EM::::::M               M::::::M")
print(" OO:::::::::::::OO  p::::::::::::::::p  e::::::::eeeeeeee    n::::n    n::::nS::::::SSSSSS:::::SI::::::::IE::::::::::::::::::::EM::::::M               M::::::M")
print("   OO:::::::::OO    p::::::::::::::pp    ee:::::::::::::e    n::::n    n::::nS:::::::::::::::SS I::::::::IE::::::::::::::::::::EM::::::M               M::::::M")
print("     OOOOOOOOO      p::::::pppppppp        eeeeeeeeeeeeee    nnnnnn    nnnnnn SSSSSSSSSSSSSSS   IIIIIIIIIIEEEEEEEEEEEEEEEEEEEEEEMMMMMMMM               MMMMMMMM")
print("                    p:::::p                                                                                                                                    ")
print("                    p:::::p                                                                                                                                    ")
print("                   p:::::::p                                                                                                                                   ")
print("                   p:::::::p                                                                                                                                   ")
print("                   p:::::::p                                                                                                                                   ")
print("                   ppppppppp                                                                                                                                   ")
print("                                                                                                                                                               ")
print("\n\n")
print("╔═╗┌┬┐┌─┐┌┬┐")
print("╠═╣ │ │ ││││")
print("╩ ╩ ┴ └─┘┴ ┴")
print("\n\n\n\n")


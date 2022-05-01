"""
CASA-IA Security system zone python plugin for Domoticz
Author: Erwanweb,
Version:    0.0.1: alpha
            0.0.2: beta
            0.0.3: validate
            0.0.4: telegram integration....
            0.0.5: Alexa integration....
"""
"""
<plugin key="SSLite" name="AC Security system LITE" author="Erwanweb" version="2.1.4" externallink="https://github.com/Erwanweb/SSLite.git">
    <description>
        <h2>Security system Lite</h2><br/>
        Easily control security system with Telegram message services and Alexa control<br/>
        <h3>Set-up and Configuration</h3>
    </description>
    <params>
        <param field="Username" label="ID Telegram Group" width="100px" required="false" default=""/>
        <param field="Password" label="Sirens with 5 levels (list of idx)" width="200px" required="false" default=""/>
        <param field="Mode1" label="Pre-detection Sensors (list of idx)" width="400px" required="false" default=""/>
        <param field="Mode2" label="Perimetral doors/windows Sensors (list of idx)" width="400px" required="false" default=""/>
        <param field="Mode3" label="Night zone Motion Sensors (list of idx)" width="400px" required="false" default=""/>
        <param field="Mode4" label="Rest of Motion Sensors (list of idx)" width="400px" required="false" default=""/>
        <param field="Mode5" label="Delays (in seconds): Arming, Detection, Sirens On, Alarm Reset - Voice(0:no,1:Alexa)" width="200px" required="true" default="60,0,60,120,0"/>
        <param field="Mode6" label="Logging Level" width="200px">
            <options>
                <option label="Normal" value="Normal"  default="true"/>
                <option label="Verbose" value="Verbose"/>
                <option label="Debug - Python Only" value="2"/>
                <option label="Debug - Basic" value="62"/>
                <option label="Debug - Basic+Messages" value="126"/>
                <option label="Debug - Connections Only" value="16"/>
                <option label="Debug - Connections+Queue" value="144"/>
                <option label="Debug - All" value="-1"/>
            </options>
        </param>
    </params>
</plugin>
"""
import Domoticz
import json
import urllib.parse as parse
import urllib.request as request
from datetime import datetime, timedelta
import time
import base64
import itertools
import os
import subprocess as sp
from distutils.version import LooseVersion

class deviceparam:

    def __init__(self, unit, nvalue, svalue):
        self.unit = unit
        self.nvalue = nvalue
        self.svalue = svalue


class BasePlugin:

    def __init__(self):

        self.debug = False
        self.Armingondelay = 30
        self.Detectiondelay = 0
        self.Alarmondelay = 30
        self.Alarmoffdelay = 90
        self.Voice = 0
        self.Sirens = []
        self.DTpreDet = []
        self.DTPerimetral = []
        self.DTNightAlarm = []
        self.DTNormaltAlarm = []
        self.AlarmReady = False
        self.NightNewDetection = False
        self.NightDetection = False
        self.NormalNewDetection = False
        self.NormalDetection = False
        self.Intrusion = False
        self.Alarm = False
        self.LastCommand = datetime.now()
        self.Softrestartingtime = datetime.now()
        self.Armingtempo = datetime.now()
        self.Perimetraltempo = datetime.now()
        self.NightAlarmtempo = datetime.now()
        self.NightDetectiontempo = datetime.now()
        self.NormalAlarmtempo = datetime.now()
        self.NormalDetectiontempo = datetime.now()
        self.Detectionchangedtime = datetime.now()
        self.LevelControltime = datetime.now()
        self.PSControltime = datetime.now()
        self.MSControltime = datetime.now()
        self.ControlSensortempo = datetime.now()
        self.DTtempoPS = datetime.now()
        self.DTtempoMS1 = datetime.now()
        self.DTtempoMS2 = datetime.now()
        self.AlarmLevel = 0
        self.CalledSensor = 0
        self.NextCalledSensor = 0
        self.NextCalledSensorPositionInListForVerification = 0
        self.VerificationPSInFunction = False
        self.VerificationMS1InFunction = False
        self.VerificationMS2InFunction = False
        self.PSactif = False
        self.Telegram = False
        self.Alexa = False
        self.VoiceLevelNormal = False
        self.VoiceAlarmLevelMax = False
        self.loglevel = None
        self.statussupported = True
        self.InternalsDefaults = {
            'Hour': 0,  # Time "Hour" of last command
            'Minute': 0,  # Time "Minutes" of last command
            'Day': 1}  # Day of last command
        self.Internals = self.InternalsDefaults.copy()
        return


    def onStart(self):

        # setup the appropriate logging level
        try:
            debuglevel = int(Parameters["Mode6"])
        except ValueError:
            debuglevel = 0
            self.loglevel = Parameters["Mode6"]
        if debuglevel != 0:
            self.debug = True
            Domoticz.Debugging(debuglevel)
            DumpConfigToLog()
            self.loglevel = "Verbose"
        else:
            self.debug = False
            Domoticz.Debugging(0)

        # create the child devices if these do not exist yet
        devicecreated = []
        if 1 not in Devices:
            Options = {"LevelActions":"||",
                       "LevelNames":"Not Ready|Disarmed|Perimetral|Night|Total",
                       "LevelOffHidden":"true",
                       "SelectorStyle":"0"}
            Domoticz.Device(Name = "Control",Unit = 1,TypeName = "Selector Switch",Switchtype = 18,Image = 9,
                            Options = Options,Used = 1).Create()
            devicecreated.append(deviceparam(1,0,"0"))  # default is Disarmed
        if 2 not in Devices:
            Domoticz.Device(Name="Surveillance Armed", Unit=2, TypeName="Switch", Image=9, Used=1).Create()
            devicecreated.append(deviceparam(2, 0, ""))  # default is Off
        if 3 not in Devices:
            Domoticz.Device(Name="Perimetral Detection", Unit=3, TypeName="Switch", Image=9, Used=1).Create()
            devicecreated.append(deviceparam(3, 0, ""))  # default is Off
        if 4 not in Devices:
            Domoticz.Device(Name="Groupe 1 Detection", Unit=4, TypeName="Switch", Image=9, Used=1).Create()
            devicecreated.append(deviceparam(4, 0, ""))  # default is Off
        if 5 not in Devices:
            Domoticz.Device(Name="Groupe 2 Detection", Unit=5, TypeName="Switch", Image=9, Used=1).Create()
            devicecreated.append(deviceparam(5, 0, ""))  # default is Off
        if 6 not in Devices:
            Domoticz.Device(Name="Intrusion Detected", Unit=6, TypeName="Switch", Image=13, Used=1).Create()
            devicecreated.append(deviceparam(6, 0, ""))  # default is Off
        if 7 not in Devices:
            Domoticz.Device(Name="Alarm", Unit=7, TypeName="Switch", Image=13, Used=1).Create()
            devicecreated.append(deviceparam(7, 0, ""))  # default is Off
        if 8 not in Devices:
            Domoticz.Device(Name="Log", Unit=8, TypeName="Alert", Used=1).Create()
            devicecreated.append(deviceparam(8, 0, ""))  # default is clear
        if 9 not in Devices:
            Options = {"LevelActions":"||",
                       "LevelNames":"Waiting|PS|MS|State",
                       "LevelOffHidden":"true",
                       "SelectorStyle":"0"}
            Domoticz.Device(Name = "Check",Unit = 9,TypeName = "Selector Switch",Switchtype = 18,Image = 9,
                            Options = Options,Used = 1).Create()
            devicecreated.append(deviceparam(9,0,"0"))  # default is waiting

        # if any device has been created in onStart(), now is time to update its defaults
        for device in devicecreated:
            Devices[device.unit].Update(nValue=device.nvalue, sValue=device.svalue)

        # build lists of alarm sensors
        self.Sirens = parseCSV(Parameters["Password"])
        Domoticz.Debug("Sirens = {}".format(self.DTPerimetral))
        self.DTpreDet = parseCSV(Parameters["Mode1"])
        Domoticz.Debug("Pre-Detection Sensors = {}".format(self.DTPerimetral))
        self.DTPerimetral = parseCSV(Parameters["Mode2"])
        Domoticz.Debug("Perimetral Sensors = {}".format(self.DTPerimetral))
        self.DTNightAlarm = parseCSV(Parameters["Mode3"])
        Domoticz.Debug("Night Motion Sensors = {}".format(self.DTNightAlarm))
        self.DTNormalAlarm = parseCSV(Parameters["Mode4"])
        Domoticz.Debug("Normal Motion Sensors = {}".format(self.DTNormalAlarm))

        # splits additional parameters
        params = parseCSV(Parameters["Mode5"])
        if len(params) == 5:
            self.Armingondelay = CheckParam("delay arming validation",params[0],30)
            self.Detectiondelay = CheckParam("delay before detection validation)",params[1],0)
            self.Alarmondelay = CheckParam("Alarm On Delay",params[2],30)
            self.Alarmoffdelay = CheckParam("Alarm Off Delay",params[3],90)
            self.Voice = CheckParam("Voice", params[4], 0)

        else:
            Domoticz.Error("Error reading Mode5 parameters")

        # detection delay on plugin starting.:

        self.Softrestartingtime = datetime.now()
        Domoticz.Debug("SS Lite plugin is just now restarting")
        self.LastCommand = datetime.now()

        if Parameters["Username"] != "":
            self.Telegram = True

        if self.Voice == 1:
            self.Alexa = True

        #Reset of positions For PS and MS verif :
        CalledSensorPositionInList = 0
        NextCalledSensorPositionInList = 0
        SensorsNumbers = 0
        self.NextCalledSensorPositionInListForVerification = 0
        self.CalledSensor = 0
        self.NextCalledSensor = 0

        # be sure called PS or MS is off-waiting position
        Devices[9].Update(nValue=0, sValue="0")

        # starting alexa API and creation of multiroom device "Alarm" for speaking on all Echo devices
        if self.Alexa :
            cmd = 'sudo /home/pi/script/alexa_remote_control.sh -lastalexa'
            Domoticz.Debug("Starting Alexa API and update cookie if necessary")
            os.system(cmd)

        # creating user variable if doesn't exist
        self.getUserVar()
        #DomoticzAPI("type=command&param=adduservariable&vname=Hour-of-last-alarme-control&vtype=0&vvalue=0")
        #DomoticzAPI("type=command&param=adduservariable&vname=Minute-of-last-alarme-control&vtype=0&vvalue=0")
        #DomoticzAPI("type=command&param=adduservariable&vname=Day-of-last-alarme-control&vtype=0&vvalue=1")

    def onStop(self):

        Domoticz.Debugging(0)


    def onCommand(self, Unit, Command, Level, Color):

        Domoticz.Debug("onCommand called for Unit {}: Command '{}', Level: {}".format(Unit, Command, Level))

        now = datetime.now()

        if self.LastCommand + timedelta(seconds=15) <= now: #tempo between 2 commands, also because alexa can send same 2 commands in very short time

            if (Unit == 1):
                Devices[1].Update(nValue = 0, sValue = str(Level))
                self.LastCommand = datetime.now()
                #time.sleep(2)
                if (Devices[2].nValue == 1): #alarm is on and armed - timer passed
                    Domoticz.Debug("Alarm is on and we try to command it")
                #if (Devices[1].sValue != "0"): #alarm ready is on or alarm already on
                    if (Devices[1].sValue == "10"): #command off
                        Domoticz.Debug("Switching Surveillance Off and so alarm Off !")
                        Devices[8].Update(nValue = 2,sValue = "Desarmement Alarme")
                        Devices[8].Update(nValue = 2,sValue = "Protection desarmee")
                        self.NightNewDetection = False
                        self.NightDetection = False
                        self.NormalNewDetection = False
                        self.NormalDetection = False
                        self.Intrusion = False
                        self.Alarm = False
                        Devices[1].Update(nValue = 0,sValue = str(Level))
                        Devices[2].Update(nValue = 0,sValue = Devices[2].sValue)
                        Devices[3].Update(nValue = 0,sValue = Devices[3].sValue)
                        Devices[4].Update(nValue = 0,sValue = Devices[4].sValue)
                        Devices[5].Update(nValue = 0,sValue = Devices[5].sValue)
                        Devices[6].Update(nValue = 0,sValue = Devices[6].sValue)
                        Devices[7].Update(nValue = 0,sValue = Devices[7].sValue)
                        self.AlarmLevel = 0
                        for idx in self.Sirens:
                            DomoticzAPI("type=command&param=switchlight&idx={}&switchcmd=Set Level&level=0".format(idx))  # Levels are 0:OFF, 10:flash, 20:siren,30:Alarm, 40:?
                        self.LevelControltime = datetime.now()
                        # modif des users variable
                        LastActionAlarmLevel = self.LevelControltime
                        # heure "Hour" et "Minute" et jour "Day2 de derniere modif
                        self.Internals['Hour'] = LastActionAlarmLevel.strftime("%-H")
                        self.Internals['Minute'] = LastActionAlarmLevel.strftime("%M")
                        self.Internals['Day'] = LastActionAlarmLevel.isoweekday()
                        self.saveUserVar()  # update user variables with latest values
                        if self.Telegram:
                            TelegramAPI("Protection Desarmee")
                        if self.Alexa:
                            AlexaAPI("La protéction anti intrusion est desactivée")

                    else : #alarm already on and we try to comman on
                        Domoticz.Debug("Trying to command ON but alarm is already ON !")
                        if self.AlarmLevel == 1 :
                            Devices[1].Update(nValue=1, sValue="20")
                        if self.AlarmLevel == 2 :
                            Devices[1].Update(nValue=1, sValue="30")
                        if self.AlarmLevel == 3:
                            Devices[1].Update(nValue=1, sValue="40")
                        Devices[8].Update(nValue=2, sValue="Commande activation impossible - Protection deja active")
                        Devices[8].Update(nValue=2, sValue="Protection active")
                        if self.Telegram:
                            TelegramAPI("Commande activation impossible - Protection deja active")
                        if self.Alexa:
                            AlexaAPI("Commande dactivation de la protéction impossible. elle est déja active. Veuillez dabord la désactiver avant de la ré activer au niveau de protection désiré")

                else : #alarm is off or in timer on timer
                    if not self.AlarmLevel == 0 : #alarm is on but in timer on period
                        if self.Telegram:
                            TelegramAPI("Commande impossible - Protection active et en cours d'initialisation")
                        if self.Alexa:
                            AlexaAPI("Commande de la protéction impossible. elle est active et en cours dinitialisation.")
                        if self.AlarmLevel == 1:
                            Devices[1].Update(nValue=1, sValue="20")
                        if self.AlarmLevel == 2:
                            Devices[1].Update(nValue=1, sValue="30")
                        if self.AlarmLevel == 3:
                            Devices[1].Update(nValue=1, sValue="40")

                    else : #alarm is full off
                        if (Devices[1].sValue == "10"):
                            if self.Telegram:
                                TelegramAPI("Commande desactivation impossible - Protection deja desactive.")
                            if self.Alexa:
                                AlexaAPI("Commande de la désactivation de la protéction impossible. elle est déja désactivée.")

                        elif self.AlarmReady: #alarm is off and ready for arming command
                            if (Devices[1].sValue == "20"):
                                Devices[1].Update(nValue=1, sValue="20")
                                Devices[8].Update(nValue=2, sValue="Protection perimetrique activee - Timer")
                                self.AlarmLevel = 1
                                if self.Telegram:
                                    TelegramAPI("Protection perimetrique activee - Timer")
                                if self.Alexa:
                                    AlexaAPI("La protéction périmetrique est activée. Initialisation en cours")
                                self.Armingtempo = datetime.now()

                            elif (Devices[1].sValue == "30"):
                                Devices[1].Update(nValue=1, sValue="30")
                                Devices[8].Update(nValue=2, sValue="Protection mode NUIT activee - Timer")
                                self.AlarmLevel = 2
                                if self.Telegram:
                                    TelegramAPI("Protection mode NUIT activee - Timer")
                                if self.Alexa:
                                    AlexaAPI("La protéction mode nuit est activée. Initialisation en cours")
                                self.Armingtempo = datetime.now()

                            elif (Devices[1].sValue == "40"):
                                Devices[1].Update(nValue=1, sValue="40")
                                Devices[8].Update(nValue=2, sValue="Protection TOTALE activee - Timer")
                                self.AlarmLevel = 3
                                if self.Telegram:
                                    TelegramAPI("Protection TOTALE activee - Timer")
                                if self.Alexa:
                                    AlexaAPI("La protéction totale est activée. Initialisation en cours")
                                self.Armingtempo = datetime.now()

                        else : #alarm is off but not alarm ready
                            Devices[1].Update(nValue=0, sValue="0")
                            Devices[8].Update(nValue=0, sValue="Commande impossible - Desarmee - Non Pret - Des capteurs périmétriques sont actifs")
                            if self.Telegram:
                                TelegramAPI( "Commande protection impossible - Desarmee - Non Pret - Des capteurs périmétriques sont actifs")
                            if self.Alexa:
                                AlexaAPI( "Commande de la protéction impossible. Des capteurs périmétriques sont actifs")
                            time.sleep(4)
                            Domoticz.Debug("Commande impossible car PS Actifs- Verification of PS - Perimetral Sensors")
                            Devices[8].Update(nValue=3, sValue="Verif PS --- Demarrage")
                            if self.Telegram:
                                TelegramAPI("Verification des PS - Capteurs perimetriques")
                            if self.Alexa:
                                AlexaAPI("Je vérifie les capteurs périmétriques")
                            Devices[9].Update(nValue=1, sValue="10")
                            time.sleep(3)
                            self.verifPS()

            if (Unit == 9):
                Devices[9].Update(nValue = 0,sValue = str(Level))
                self.LastCommand = datetime.now()
                if (Devices[9].sValue == "10"):
                    Devices[9].Update(nValue=1, sValue="10")
                    Devices[8].Update(nValue=3, sValue="Verif PS --- Demarrage")
                    Domoticz.Debug("Verification of PS - Perimetral Sensors")
                    if self.Telegram:
                        TelegramAPI("Verification des PS - Capteurs perimetriques" )
                    if self.Alexa:
                        AlexaAPI("Je vérifie les capteurs périmétriques")
                    time.sleep(5)
                    self.verifPS()

                if (Devices[9].sValue == "20"):
                    Devices[9].Update(nValue = 1,sValue = "20")
                    Devices[8].Update(nValue=3, sValue="Verif MS --- Demarrage")
                    Domoticz.Debug("Verification of MS - Motion Sensors")
                    if self.Telegram:
                        TelegramAPI("Verification des MS - Capteurs de mouvements")
                    if self.Alexa:
                        AlexaAPI("Je vérifie les capteurs de présence")
                    time.sleep(5)
                    self.verifMS1()

                if (Devices[9].sValue == "30"):
                    Devices[9].Update(nValue = 1,sValue = "30")
                    #Devices[8].Update(nValue=3, sValue="Verif Etat --- Demarrage")
                    Domoticz.Debug("Verification etat protection")
                    self.verifAlarmState()

        #self.onHeartbeat()


    def onHeartbeat(self):

        # fool proof checking....
        if not all(device in Devices for device in (1,2,3,4,5,6,7,8,9)):
            Domoticz.Error("one or more devices required by the plugin is/are missing, please check domoticz device creation settings and restart !")
            return

        now = datetime.now()

        #self.PerimetralDetection()  # checking when alarm is off if perimetral is ok,  for arming possibility,

        if (Devices[1].nValue == 0):  # Surveillance is off but we check if perimetral is ok, if not, unable to turn on protection
            self.PerimetralDetection()  # checking when alarm is off if perimetral is ok,  for arming possibility,
            if Devices[3].nValue == 0:
                self.AlarmReady = True
                if (Devices[1].sValue == "0"):
                    Devices[1].Update(nValue = 0,sValue = "10")
                    Devices[8].Update(nValue = 1,sValue = "Desarmee - Pret")

            else:
                self.AlarmReady = False
                if (Devices[1].sValue == "10"):
                    Devices[1].Update(nValue = 0,sValue = "0")
                    Devices[8].Update(nValue = 0,sValue = "Desarmee - Non Pret - Verifier capteurs perimetriques")

            if (Devices[8].nValue >= 2):
                if self.AlarmReady:
                    Devices[8].Update(nValue = 1,sValue = "Desarmee - Pret")
                else:
                    Devices[8].Update(nValue = 0,sValue = "Desarmee - Non Pret - Verifier capteurs perimetriques")

        if (Devices[1].nValue == 0):  # Surveillance is off
            Domoticz.Log("Surveillance desactived...")
            if self.Alarm:  # Surveillance setting was just changed so we kill the surveillance of the zone and stop the eventual alarm
                self.NightNewDetection = False
                self.NightDetection = False
                self.NormalNewDetection = False
                self.NormalDetection = False
                self.Intrusion = False
                self.Alarm = False
                if Devices[2].nValue == 1:
                    Devices[2].Update(nValue = 0,sValue = Devices[2].sValue)
                if Devices[3].nValue == 1:
                    Devices[3].Update(nValue = 0,sValue = Devices[3].sValue)
                if Devices[4].nValue == 1:
                    Devices[4].Update(nValue = 0,sValue = Devices[4].sValue)
                if Devices[5].nValue == 1:
                    Devices[5].Update(nValue = 0,sValue = Devices[5].sValue)
                if Devices[6].nValue == 1:
                    Devices[6].Update(nValue = 0,sValue = Devices[6].sValue)
                if Devices[7].nValue == 1:
                    Devices[7].Update(nValue = 0,sValue = Devices[7].sValue)
                    for idx in self.Sirens:
                        DomoticzAPI("type=command&param=switchlight&idx={}&switchcmd=Set Level&level=0".format(idx))  # Levels are 0:OFF, 10:Alarm, 20:siren,30:Flash, 40:Arm, 50:Disarm


        else: # At Mini Perimetral Surveillance is on
            if self.Softrestartingtime + timedelta(seconds = (self.Armingondelay + 1)) <= now:

                if self.Armingtempo + timedelta(seconds = self.Armingondelay) <= now:
                    if Devices[2].nValue == 0:
                        Devices[2].Update(nValue = 1,sValue = Devices[2].sValue)
                        #if self.Softrestartingtime + timedelta(minutes = 5) <= now:
                        Domoticz.Log("Arming on delay passed - Alarme Armed...")
                        Devices[8].Update(nValue=2, sValue="Surveillance commencee")
                        Devices[8].Update(nValue=2, sValue="Protection active")
                        self.LevelControltime = datetime.now()
                        #modif des users variable
                        LastActionAlarmLevel = self.LevelControltime
                        #heure "Hour" et "Minute" et jour "Day2 de derniere modif
                        self.Internals['Hour'] = LastActionAlarmLevel.strftime("%-H")
                        self.Internals['Minute'] = LastActionAlarmLevel.strftime("%M")
                        self.Internals['Day'] = LastActionAlarmLevel.isoweekday()
                        self.saveUserVar()  # update user variables with latest values
                        if self.Telegram:
                            TelegramAPI("Surveillance commencee - Protection active")
                        if self.Alexa:
                            AlexaAPI("Linitialisation de la protéction est terminée et elle est maintenant active")


                else :
                    Domoticz.Log("Alarm Armed but in timer ON period !")
                    if Devices[2].nValue == 1:
                        Devices[2].Update(nValue = 0,sValue = Devices[2].sValue)
                    if Devices[3].nValue == 1:
                        Devices[3].Update(nValue = 0,sValue = Devices[3].sValue)
                    if Devices[4].nValue == 1:
                        Devices[4].Update(nValue = 0,sValue = Devices[4].sValue)
                    if Devices[5].nValue == 1:
                        Devices[5].Update(nValue = 0,sValue = Devices[5].sValue)
                    if Devices[6].nValue == 1:
                        Devices[6].Update(nValue = 0,sValue = Devices[6].sValue)
                    if Devices[7].nValue == 1:
                        Devices[7].Update(nValue = 0,sValue = Devices[7].sValue)


            if Devices[2].nValue == 1:
                if (Devices[1].sValue == "20"):  # perimetral Surveillance is on
                    self.AlarmLevel = 1
                    Domoticz.Log("Perimetral Surveillance is actived...")
                    self.PerimetralDetection()

                if (Devices[1].sValue == "30"):  # Night Surveillance is on
                    self.AlarmLevel = 2
                    Domoticz.Log("Night Surveillance is actived...")
                    self.PerimetralDetection()
                    self.NightMotionDetection()

                if (Devices[1].sValue == "40"):  # Total Surveillance is on
                    self.AlarmLevel = 3
                    Domoticz.Log("Total Surveillance is actived...")
                    self.PerimetralDetection()
                    self.NightMotionDetection()
                    self.NormalMotionDetection()

                self.AlarmDetection()

    def verifAlarmState(self):

        #time.sleep(2)
        now = datetime.now()
        #Recup user variables
        HouroflastactiononAlarmLevel = self.Internals['Hour']
        MinuteoflastactiononAlarmLevel = self.Internals['Minute']
        DayoflastactiononAlarmLevel = self.Internals['Day']
        #self.LevelControltime = datetime.now()
        #Days = ["Lundi", "Mardi", "Mercredi", "Jeudi", "Vendredi", "Samedi", "Dimanche"]
        #LastActionAlarmLevel = self.LevelControltime
        #Time = LastActionAlarmLevel.strftime("%-H heure %M")
        #Day = LastActionAlarmLevel.strftime("%A") # in english
        #DayoflastactiononAlarmLevel = LastActionAlarmLevel.today().strftime("%u")
        #DayoflastactiononAlarmLevel = LastActionAlarmLevel.today().isoweekday()
        #DayoflastactiononAlarmLevel = LastActionAlarmLevel.isoweekday()
        Todayintext = datetime.now().strftime("%u")
        Today = datetime.now().isoweekday()
        LastActionDayintext = Todayintext
        # For debug only
        Domoticz.Debug("----> Check days today is {} and last action is {} ".format(Today, DayoflastactiononAlarmLevel))
        if self.Telegram:
            TelegramAPI("----> Check days today is {} and last action is {} ".format(Today, DayoflastactiononAlarmLevel))
            # End of for debug only
        if Today == DayoflastactiononAlarmLevel :
            LastActionDayintext = "Aujourdhui"
        elif Today == (DayoflastactiononAlarmLevel + 1) or Today == (DayoflastactiononAlarmLevel - 6):
            LastActionDayintext = "Hier"
        else:
            if DayoflastactiononAlarmLevel == 1:
                LastActionDayintext = "Lundi"
            if DayoflastactiononAlarmLevel == 2:
                LastActionDayintext = "Mardi"
            if DayoflastactiononAlarmLevel == 3:
                LastActionDayintext = "Mercredi"
            if DayoflastactiononAlarmLevel == 4:
                LastActionDayintext = "Jeudi"
            if DayoflastactiononAlarmLevel == 5:
                LastActionDayintext = "Vendredi"
            if DayoflastactiononAlarmLevel == 6:
                LastActionDayintext = "Samedi"
            if DayoflastactiononAlarmLevel == 7:
                LastActionDayintext = "Dimanche"

        
        Domoticz.Debug("----> Last action on Alarm level is on {} at {} H {} ".format(DayoflastactiononAlarmLevel, HouroflastactiononAlarmLevel, MinuteoflastactiononAlarmLevel))
        Domoticz.Debug("----> In french : {} a {} H {}".format(LastActionDayintext, HouroflastactiononAlarmLevel, MinuteoflastactiononAlarmLevel))


        if Devices[1].nValue == 0:
            Domoticz.Log("--Alarm - Check State : OFF...")
            if self.Alexa:
                AlexaAPI("La protection est désactivé depuis {} a {} heure {}".format(LastActionDayintext, HouroflastactiononAlarmLevel, MinuteoflastactiononAlarmLevel))
        else:
            if Devices[2].nValue == 1:
                if self.AlarmLevel == 1:
                    Domoticz.Log("--Alarm - Check State : Active level Perimetral...")
                    if self.Alexa:
                        AlexaAPI("La protection est active en mode périmétrique depuis {} a {} heure {}".format(LastActionDayintext, HouroflastactiononAlarmLevel, MinuteoflastactiononAlarmLevel))
                if self.AlarmLevel == 2:
                    Domoticz.Log("--Alarm - Check State : Active level Night...")
                    if self.Alexa:
                        AlexaAPI("La protection est active en mode nuit depuis {} a {} heure {}".format(LastActionDayintext, HouroflastactiononAlarmLevel, MinuteoflastactiononAlarmLevel))
                if self.AlarmLevel == 3:
                    Domoticz.Log("--Alarm - Check State : Active level Total...")
                    if self.Alexa:
                        AlexaAPI("La protection est active en mode général depuis {} a {} heure {}".format(LastActionDayintext, HouroflastactiononAlarmLevel, MinuteoflastactiononAlarmLevel))
            else:
                if self.AlarmLevel == 1:
                    Domoticz.Log("--Alarm - Check State : Initialization level Perimetral...")
                    if self.Alexa:
                        AlexaAPI("La protection a été activé en mode périmétrique a {} heure {} mais elle est en cours dinitialisation".format(HouroflastactiononAlarmLevel, MinuteoflastactiononAlarmLevel))
                if self.AlarmLevel == 2:
                    Domoticz.Log("--Alarm - Check State : Initialization level Night...")
                    if self.Alexa:
                        AlexaAPI("La protection a été activé en mode nuit a {} heure {} mais elle est en cours dinitialisation".format(HouroflastactiononAlarmLevel, MinuteoflastactiononAlarmLevel))
                if self.AlarmLevel == 3:
                    Domoticz.Log("--Alarm - Check State : Initialization level Total...")
                    if self.Alexa:
                        AlexaAPI("La protection a été activé en mode général a {} heure {} mais elle est en cours dinitialisation".format(HouroflastactiononAlarmLevel, MinuteoflastactiononAlarmLevel))

        time.sleep(5)
        Devices[9].Update(nValue=0, sValue="0")

    def verifPS(self):

        now = datetime.now()

        self.VerificationPSInFunction = True
        self.PSactif = False

        Domoticz.Log("--- Verification of PS Called...")
        params = parseCSV(Parameters["Mode2"])
        Domoticz.Debug("PS Listed are = {}".format(params))
        SensorsNumbers = len(params)
        Domoticz.Debug("Quantity of PS Listed is : {}".format(SensorsNumbers))
        CalledSensorPositionInList = self.NextCalledSensorPositionInListForVerification
        NextCalledSensorPositionInList = (CalledSensorPositionInList + 1)
        self.NextCalledSensorPositionInListForVerification = NextCalledSensorPositionInList
        if CalledSensorPositionInList < SensorsNumbers:
            Domoticz.Debug("PS Called position in list is = {}".format(CalledSensorPositionInList))
            # self.CalledPS = CheckParam("DT Checked", params[self.CalledSensorPositionInList], 1)
            self.CalledSensor = params[CalledSensorPositionInList]
            Domoticz.Debug("PS Called is = {}".format(self.CalledSensor))
            if NextCalledSensorPositionInList < SensorsNumbers:
                self.NextCalledSensor = params[NextCalledSensorPositionInList]
                Domoticz.Debug("Next PS Called will be = {}".format(self.NextCalledSensor))
            else:
                Domoticz.Debug("PS Called with position {} and Idx {} is the last in the PS list !!! ".format(CalledSensorPositionInList, self.CalledSensor))
            # we check the alarm sensor
            devicesAPI = DomoticzAPI("type=devices&filter=light&used=true&order=Name")
            if devicesAPI:
                for device in devicesAPI["result"]:  # parse the perimetral sensors (PS) devices
                    idx = int(device["idx"])
                    if idx == self.CalledSensor:  # this is one of our PS
                        if "Status" in device:
                            # PerimetralDT[idx] = True if device["Status"] == "On" else False
                            Domoticz.Debug(
                                "Verif : PS Sensor idx {}, '{}' currently is '{}'".format(idx, device["Name"], device["Status"]))
                            if not device["Status"] == "Off" :
                                if not device["Status"] == "Closed" :
                                    self.PSactif = True
                            if not device["Status"] == "Closed" :
                                if not device["Status"] == "Off":
                                    self.PSactif = True                                    
                            if self.PSactif :
                                Devices[8].Update(nValue=3, sValue="Verif PS en cours : --- '{}' - '{}'".format(device["Name"], device["Status"]))
                                self.DTtempoPS = datetime.now()
                                if self.Telegram:
                                    TelegramAPI("--- Actif : '{}'".format(device["Name"]))
                                if self.Alexa:
                                    if not self.Intrusion:
                                        AlexaAPI("Le {} est actif ".format(device["Name"]))
                                    else:
                                        AlexaAlarmAPI("Détection {}".format(device["Name"]))
                                    time.sleep(2)
                                    self.verifPS()
                                else:
                                    self.verifPS()
                            else:
                                self.verifPS()
        else:
            Domoticz.Debug("--- PS Called with position {} and Idx {} was the last in the PS list !!! ".format((CalledSensorPositionInList -1), self.CalledSensor))
            CalledSensorPositionInList = 0
            NextCalledSensorPositionInList = 0
            SensorsNumbers = 0
            self.NextCalledSensorPositionInListForVerification = 0
            self.CalledSensor = 0
            self.NextCalledSensor = 0
            Domoticz.Debug("--- Reset of sensor called and next called position in list by  '{}' and '{}'".format(CalledSensorPositionInList, NextCalledSensorPositionInList))
            # time.sleep(5)
            if (Devices[9].nValue == 1):  # self.VerifPS was called by Verif PS action
                Domoticz.Debug("Verif PS done...")
                Devices[8].Update(nValue=3, sValue="Verif PS --- terminee")
                if self.DTtempoPS + timedelta(seconds=30) >= now:  # there is at mini 1 PS that was ON in the past 60 seconds
                    Domoticz.Debug("Verif PS -> SOME AR ON")
                    Devices[8].Update(nValue=3, sValue="Vérifiez les capteurs actifs")
                    if self.Telegram:
                        TelegramAPI("Vérification des capteurs périmétriques terminé. Vérifiez les capteurs actifs")
                    if self.Alexa:
                        AlexaAPI("Vérification des capteurs périmétriques terminé. Vérifiez les capteurs actifs")
                else:
                    Domoticz.Debug("Verif PS -> ALL OK")
                    Devices[8].Update(nValue=3, sValue="Verif PS --- ALL OK")
                    if self.Telegram:
                        TelegramAPI("Vérification des capteurs périmétriques terminée : OK - Vous pouvez activer la protection")
                    if self.Alexa:
                        AlexaAPI("Vérification des capteurs périmétriques terminé. Toute est OK. vous pouvez activer la protéction")
                Devices[9].Update(nValue=0, sValue="0")
            #Stopping check of sensor step by step
            Domoticz.Log("--- Stopping Verification of PS...")
            self.VerificationPSInFunction = False
            time.sleep(1)
            #self.onHeartbeat()

    def verifMS1(self):

        now = datetime.now()

        self.VerificationMS1InFunction = True

        Domoticz.Log("--- Verification of MS1 Night zone Called...")
        params = parseCSV(Parameters["Mode3"])
        Domoticz.Debug("MS group 1 Listed are = {}".format(params))
        SensorsNumbers = len(params)
        Domoticz.Debug("Quantity of MS Listed is : {}".format(SensorsNumbers))
        CalledSensorPositionInList = self.NextCalledSensorPositionInListForVerification
        NextCalledSensorPositionInList = (CalledSensorPositionInList + 1)
        self.NextCalledSensorPositionInListForVerification = NextCalledSensorPositionInList
        if CalledSensorPositionInList < SensorsNumbers:
            Domoticz.Debug("MS Called position in list is = {}".format(CalledSensorPositionInList))
            # self.CalledPS = CheckParam("DT Checked", params[self.CalledSensorPositionInList], 1)
            self.CalledSensor = params[CalledSensorPositionInList]
            Domoticz.Debug("MS Called is = {}".format(self.CalledSensor))
            if NextCalledSensorPositionInList < SensorsNumbers:
                self.NextCalledSensor = params[NextCalledSensorPositionInList]
                Domoticz.Debug("Next MS Called will be = {}".format(self.NextCalledSensor))
            else:
                Domoticz.Debug("MS Called with position {} and Idx {} is the last in the MS Group 1 list !!! ".format(CalledSensorPositionInList, self.CalledSensor))
            # we check the alarm sensor
            devicesAPI = DomoticzAPI("type=devices&filter=light&used=true&order=Name")
            if devicesAPI:
                for device in devicesAPI["result"]:  # parse the perimetral sensors (PS) devices
                    idx = int(device["idx"])
                    if idx == self.CalledSensor:  # this is one of our PS
                        if "Status" in device:
                            # PerimetralDT[idx] = True if device["Status"] == "On" else False
                            Domoticz.Debug(
                                "Verif : MS Sensor idx {}, '{}' currently is '{}'".format(idx, device["Name"], device["Status"]))
                            if device["Status"] == "On":
                                Devices[8].Update(nValue=3, sValue="Verif MS en cours : --- '{}' - '{}'".format(device["Name"], device["Status"]))
                                self.DTtempoMS1 = datetime.now()
                                if self.Telegram:
                                    TelegramAPI("--- Actif : '{}'".format(device["Name"]))
                                if self.Alexa:
                                    if not self.Intrusion :
                                        AlexaAPI("Le {} est actif ".format(device["Name"]))
                                    else :
                                        AlexaAlarmAPI("Détection {}".format(device["Name"]))
                                    time.sleep(2)
                                    self.verifMS1()
                                else:
                                    self.verifMS1()
                            else:
                                self.verifMS1()
        else:
            Domoticz.Debug("--- MS Called with position {} and Idx {} was the last in the MS Group 1 list !!! ".format((CalledSensorPositionInList -1), self.CalledSensor))
            CalledSensorPositionInList = 0
            NextCalledSensorPositionInList = 0
            SensorsNumbers = 0
            self.NextCalledSensorPositionInListForVerification = 0
            self.CalledSensor = 0
            self.NextCalledSensor = 0
            Domoticz.Debug("--- Reset of sensor called and next called position in list by  '{}' and '{}'".format(CalledSensorPositionInList, NextCalledSensorPositionInList))
            # time.sleep(5)
            if (Devices[9].nValue == 1):  # self.VerifMS1 was called by Verif MS night action
                Domoticz.Debug("Verif MS Groupe 1 - Night Zone -  done...")
                Devices[8].Update(nValue=3, sValue="Verif MS Groupe 1 - Night Zone --- terminee")
                if self.DTtempoMS1 + timedelta(seconds=30) >= now:  # there is at mini 1 PS that was ON in the past 60 seconds
                    Domoticz.Debug("Verif MS -> SOME AR ON")
                    Devices[8].Update(nValue=3, sValue="Vérifiez les capteurs actifs")
                    if self.Telegram:
                        TelegramAPI("Vérification des capteurs MS Groupe 1 - Night Zone terminé. Vérifiez les capteurs actifs")
                    if self.Alexa:
                        AlexaAPI("Vérification des capteurs de présence du Groupe 1 - Zone nuit terminé. Vérifiez les capteurs actifs")
                else:
                    Domoticz.Debug("Verif MS1 -> ALL OK")
                    Devices[8].Update(nValue=3, sValue="Verif MS1 --- ALL OK")
                    if self.Telegram:
                        TelegramAPI("Vérification des capteurs MS Groupe 1 - Night Zone terminé - ALL OK")
                    if self.Alexa:
                        AlexaAPI("Vérification des capteurs de présence du Groupe 1 - Zone nuit terminé. Toute est OK")
                #Devices[9].Update(nValue=0, sValue="0")
                time.sleep(5)
                self.verifMS2()
            #Stopping check of sensor step by step
            Domoticz.Log("--- Stopping Verification of MS1 Night zone...")
            self.VerificationMS1InFunction = False
            time.sleep(1)
            #self.onHeartbeat()

    def verifMS2(self):

        now = datetime.now()

        self.VerificationMS2InFunction = True

        Domoticz.Log("--- Verification of MS2 General zone Called...")
        params = parseCSV(Parameters["Mode4"])
        Domoticz.Debug("MS Listed in Group 2 are = {}".format(params))
        SensorsNumbers = len(params)
        Domoticz.Debug("Quantity of MS Listed is : {}".format(SensorsNumbers))
        CalledSensorPositionInList = self.NextCalledSensorPositionInListForVerification
        NextCalledSensorPositionInList = (CalledSensorPositionInList + 1)
        self.NextCalledSensorPositionInListForVerification = NextCalledSensorPositionInList
        if CalledSensorPositionInList < SensorsNumbers:
            Domoticz.Debug("MS Called position in list is = {}".format(CalledSensorPositionInList))
            # self.CalledPS = CheckParam("DT Checked", params[self.CalledSensorPositionInList], 1)
            self.CalledSensor = params[CalledSensorPositionInList]
            Domoticz.Debug("MS Called is = {}".format(self.CalledSensor))
            if NextCalledSensorPositionInList < SensorsNumbers:
                self.NextCalledSensor = params[NextCalledSensorPositionInList]
                Domoticz.Debug("Next MS Called will be = {}".format(self.NextCalledSensor))
            else:
                Domoticz.Debug("MS Called with position {} and Idx {} is the last in the MS Groupe 2 list !!! ".format(CalledSensorPositionInList, self.CalledSensor))
            # we check the alarm sensor
            devicesAPI = DomoticzAPI("type=devices&filter=light&used=true&order=Name")
            if devicesAPI:
                for device in devicesAPI["result"]:  # parse the perimetral sensors (PS) devices
                    idx = int(device["idx"])
                    if idx == self.CalledSensor:  # this is one of our PS
                        if "Status" in device:
                            # PerimetralDT[idx] = True if device["Status"] == "On" else False
                            Domoticz.Debug(
                                "Verif : PS Sensor idx {}, '{}' currently is '{}'".format(idx, device["Name"], device["Status"]))
                            if device["Status"] == "On":
                                Devices[8].Update(nValue=3, sValue="Verif PS en cours : --- '{}' - '{}'".format(device["Name"], device["Status"]))
                                self.DTtempoMS2 = datetime.now()
                                if self.Telegram:
                                    TelegramAPI("--- Actif : '{}'".format(device["Name"]))
                                if self.Alexa:
                                    if not self.Intrusion:
                                        AlexaAPI("Le {} est actif ".format(device["Name"]))
                                    else:
                                        AlexaAlarmAPI("Détection {}".format(device["Name"]))
                                    time.sleep(2)
                                    self.verifMS2()
                                else:
                                    self.verifMS2()
                            else:
                                self.verifMS2()
        else:
            Domoticz.Debug("--- MS Called with position {} and Idx {} was the last in the MS Group 2 list !!! ".format((CalledSensorPositionInList -1), self.CalledSensor))
            CalledSensorPositionInList = 0
            NextCalledSensorPositionInList = 0
            SensorsNumbers = 0
            self.NextCalledSensorPositionInListForVerification = 0
            self.CalledSensor = 0
            self.NextCalledSensor = 0
            Domoticz.Debug("--- Reset of sensor called and next called position in list by  '{}' and '{}'".format(CalledSensorPositionInList, NextCalledSensorPositionInList))
            # time.sleep(5)
            if (Devices[9].nValue == 1):  # self.VerifMS1 was called by Verif MS night action
                Domoticz.Debug("Verif MS Groupe 2 - General Zone -  done...")
                Devices[8].Update(nValue=3, sValue="Verif MS Groupe 1 - Night Zone --- terminee")
                if self.DTtempoMS2 + timedelta(seconds=30) >= now:  # there is at mini 1 PS that was ON in the past 60 seconds
                    Domoticz.Debug("Verif PS -> SOME AR ON")
                    Devices[8].Update(nValue=3, sValue="Vérifiez les capteurs actifs")
                    if self.Telegram:
                        TelegramAPI("Vérification des capteurs MS Groupe 2 - Zone Génerale terminé. Vérifiez les capteurs actifs")
                    if self.Alexa:
                        AlexaAPI("Vérification des capteurs de présence du Groupe 2 - Zone Génerale terminé. Vérifiez les capteurs actifs")
                else:
                    Domoticz.Debug("Verif MS -> ALL OK")
                    Devices[8].Update(nValue=3, sValue="Verif PS --- ALL OK")
                    if self.Telegram:
                        TelegramAPI("Vérification des capteurs Groupe 2 - Zone Génerale terminé - ALL OK")
                    if self.Alexa:
                        AlexaAPI("Vérification des capteurs de présence du Groupe 2 - Zone Génerale terminé. Toute est OK")
                Devices[9].Update(nValue=0, sValue="0")
            #Stopping check of sensor step by step
            Domoticz.Log("--- Stopping Verification of MS2 General zone...")
            self.VerificationMS2InFunction = False
            time.sleep(1)
            #self.onHeartbeat()

    def PerimetralDetection(self):

        now = datetime.now()
        self.PSactif = False

        Domoticz.Log("Perimetral Detection called...")

        # Build list of Perimetral switches, with their current status
        PerimetralDT = {}
        devicesAPI = DomoticzAPI("type=devices&filter=light&used=true&order=Name")
        if devicesAPI:
            for device in devicesAPI["result"]:  # parse the presence/motion sensors (DT) device
                idx = int(device["idx"])
                if idx in self.DTPerimetral:  # this is one of our DT
                    if "Status" in device:
                        PerimetralDT[idx] = True if device["Status"] == "On" else False
                        Domoticz.Debug("Perimetral DT switch idx {}, '{}' currently is '{}'".format(idx,device["Name"],device["Status"]))
                        if not device["Status"] == "Off" :
                            if not device["Status"] == "Closed" :
                                self.PSactif = True
                        if not device["Status"] == "Closed" :
                            if not device["Status"] == "Off":
                                self.PSactif = True                                    
                        if self.PSactif :
                            self.Perimetraltempo = datetime.now()
                            if Devices[2].nValue == 1:
                                Devices[8].Update(nValue = 3,sValue = "--- DETECTION PERIMETRIQUE: '{}'".format(device["Name"]))
                                self.PSactif = False
                                #if self.Telegram:
                                    #TelegramAPI("--- DETECTION PERIMETRIQUE: '{}'".format(device["Name"]))
                                #if self.Alexa:
                                    #AlexaAlarmAPI("Détéction périmétrique {}".format(device["Name"]))


                    else:
                        Domoticz.Error("Device with idx '{}' and named '{}' does not seem to be a PS !".format(idx, device["Name"]))

        if self.Softrestartingtime + timedelta(seconds = (self.Armingondelay + 1)) <= now:  # wait for any detection if domoticz is just restarting;

            if self.Perimetraltempo + timedelta(seconds = 15) >= now:
                Domoticz.Debug("At mini 1 perimetral PS switch is ON or was ON in the past 15 seconds...")
                if Devices[3].nValue == 0:
                    Devices[3].Update(nValue = 1,sValue = Devices[3].sValue)
            else:
                if Devices[3].nValue == 1:
                    Devices[3].Update(nValue = 0,sValue = Devices[3].sValue)

            if (Devices[1].nValue == 1):  # Surveillance is on
                if Devices[2].nValue == 1:
                    if Devices[3].nValue == 1:
                        if Devices[6].nValue == 1:
                            Domoticz.Debug("There is intrusion but already registred...")
                        else:
                            Domoticz.Log("New intrusion...")
                            Devices[6].Update(nValue = 1,sValue = Devices[6].sValue)
                            Devices[8].Update(nValue = 3,sValue = "INTRUSION PERIMETRIQUE DETECTEE - IDENTIFICATION REQUISE")
                            if self.Telegram:
                                TelegramAPI("INTRUSION PERIMETRIQUE DETECTEE - IDENTIFICATION REQUISE")
                            if self.Alexa:
                                AlexaAlarmAPI("Attention. Intrusion périmétrique détéctée. Identification requise")
                            self.Intrusion = True
                            self.Detectionchangedtime = datetime.now()
                            time.sleep(5)
                            self.verifPS()

        else :
            if Devices[3].nValue == 1:
                Devices[3].Update(nValue = 0,sValue = Devices[3].sValue)

    def NightMotionDetection(self):

        now = datetime.now()

        Domoticz.Log("Night Motion Detection called...")

        # Build list of Alarm sensor (switches), with their current status
        NightAlarmDT = {}
        devicesAPI = DomoticzAPI("type=devices&filter=light&used=true&order=Name")
        if devicesAPI:
            for device in devicesAPI["result"]:  # parse the presence/motion sensors (switch) device
                idx = int(device["idx"])
                if idx in self.DTNightAlarm:  # this is one of our presence/motion sensors
                    if "Status" in device:
                        NightAlarmDT[idx] = True if device["Status"] == "On" else False
                        Domoticz.Debug("DT switch idx {}, '{}' currently is '{}'".format(idx,device["Name"],device["Status"]))
                        if device["Status"] == "On":
                            self.NightAlarmtempo = datetime.now()
                            if Devices[2].nValue == 1:
                                Devices[8].Update(nValue = 3,sValue = "--- DETECTION GROUPE 1 : '{}'".format(device["Name"]))
                                #if self.Telegram:
                                    #TelegramAPI("--- DETECTION GROUPE 1 : '{}'".format(device["Name"]))
                                #if self.Alexa:
                                    #AlexaAlarmAPI("Détéction intrusion {}".format(device["Name"]))

                    else:
                        Domoticz.Error("Device with idx={} does not seem to be a DT !".format(idx))

        if self.Softrestartingtime + timedelta(seconds = (self.Armingondelay + 1)) <= now:  # wait for any detection if domoticz is just restarting;

            if self.NightAlarmtempo + timedelta(seconds = 15) >= now:
                self.NightNewDetection = True
                Domoticz.Debug("At mini 1 Alarm sensor is ON or Was ON in the past 15 seconds...")
            else:
                self.NightNewDetection = False
                Domoticz.Debug("No Detection, All OK, No Alarm !")

            if self.NightNewDetection:
                if Devices[4].nValue == 1:
                    Domoticz.Debug("There is detection but already registred...")
                else:
                    Domoticz.Log("New Detection...")
                    Devices[4].Update(nValue = 1,sValue = Devices[4].sValue)
                    self.NightDetection = True
                    self.NightDetectiontempo = datetime.now()
            else:
                if Devices[4].nValue == 0:
                    Domoticz.Debug("No detection, detection already OFF...")
                else:
                    Domoticz.Debug("No detection in detection delay...")
                    Devices[4].Update(nValue = 0,sValue = Devices[4].sValue)
                    self.NightDetection = False

            if self.NightDetection:
                if Devices[6].nValue == 1:
                    Domoticz.Debug("There is intrusion but already registred...")
                else:
                    Domoticz.Log("New intrusion...")
                    Devices[6].Update(nValue = 1,sValue = Devices[6].sValue)
                    Devices[8].Update(nValue = 3,sValue = "INTRUSION DETECTEE GROUPE 1 - IDENTIFICATION REQUISE")
                    if self.Telegram:
                        TelegramAPI("INTRUSION DETECTEE GROUPE 1 - IDENTIFICATION REQUISE")
                    if self.Alexa:
                        AlexaAlarmAPI("Attention. Intrusion détéctée. groupe 1. Zone nuit. Identification requise")
                    self.Intrusion = True
                    self.Detectionchangedtime = datetime.now()
                    time.sleep(5)
                    self.verifMS1()

        else :
            if Devices[4].nValue == 1:
                Devices[4].Update(nValue = 0,sValue = Devices[4].sValue)

    def NormalMotionDetection(self):

        now = datetime.now()

        Domoticz.Log("Total Motion Detection called...")

        # Build list of Alarm sensor (switches), with their current status
        NormalAlarmDT = {}
        devicesAPI = DomoticzAPI("type=devices&filter=light&used=true&order=Name")
        if devicesAPI:
            for device in devicesAPI["result"]:  # parse the presence/motion sensors (switch) device
                idx = int(device["idx"])
                if idx in self.DTNormalAlarm:  # this is one of our presence/motion sensors
                    if "Status" in device:
                        NormalAlarmDT[idx] = True if device["Status"] == "On" else False
                        Domoticz.Debug("DT switch idx {}, '{}' currently is '{}'".format(idx,device["Name"],device["Status"]))
                        if device["Status"] == "On":
                            self.NormalAlarmtempo = datetime.now()
                            if Devices[2].nValue == 1:
                                Devices[8].Update(nValue = 3,sValue = "--- DETECTION GROUPE 2 :  '{}'".format(device["Name"]))
                                #if self.Telegram:
                                    #TelegramAPI("--- DETECTION GROUPE 2 :  '{}'".format(device["Name"]))
                                #if self.Alexa:
                                    #AlexaAlarmAPI("Détéction intrusion {}".format(device["Name"]))

                    else:
                        Domoticz.Error("Device with idx={} does not seem to be a DT !".format(idx))

        if self.Softrestartingtime + timedelta(seconds = (self.Armingondelay + 1)) <= now:  # wait for any detection if domoticz is just restarting;

            if self.NormalAlarmtempo + timedelta(seconds = 15) >= now:
                self.NormalNewDetection = True
                Domoticz.Debug("At mini 1 Alarm sensor is ON or Was ON in the past 15 seconds...")
            else:
                self.NormalNewDetection = False
                Domoticz.Debug("No Detection, All OK, No Alarm !")

            if self.NormalNewDetection:
                if Devices[5].nValue == 1:
                    Domoticz.Debug("There is detection but already registred...")
                else:
                    Domoticz.Log("New Detection...")
                    Devices[5].Update(nValue = 1,sValue = Devices[5].sValue)
                    self.NormalDetection = True

            else:
                if Devices[5].nValue == 0:
                    Domoticz.Debug("No detection, detection already OFF...")
                else:
                    Domoticz.Debug("No detection in detection delay...")
                    Devices[5].Update(nValue = 0,sValue = Devices[5].sValue)
                    self.NormalDetection = False

            if self.NormalDetection:
                if Devices[6].nValue == 1:
                    Domoticz.Debug("There is intrusion but already registred...")
                else:
                    Domoticz.Log("New intrusion...")
                    Devices[6].Update(nValue = 1,sValue = Devices[6].sValue)
                    Devices[8].Update(nValue = 3,sValue = "INTRUSION DETECTEE GROUPE 2 - IDENTIFICATION REQUISE")
                    if self.Telegram:
                        TelegramAPI("INTRUSION DETECTEE GROUPE 2 - IDENTIFICATION REQUISE")
                    if self.Alexa:
                        AlexaAlarmAPI("Attention. Intrusion détéctée. groupe 2. Zone générale. Identification requise")
                    self.Intrusion = True
                    self.Detectionchangedtime = datetime.now()
                    time.sleep(5)
                    self.verifMS2()
        else :
            if Devices[5].nValue == 1:
                Devices[5].Update(nValue = 0,sValue = Devices[5].sValue)

    def AlarmDetection(self):

        now = datetime.now()

        if self.Intrusion:
            if not self.Alarm:
                if self.Alarmondelay == 0:
                    Domoticz.Debug("Intrusion Detected and alarm setted as imediate : Alarm ACTIVE !")
                    self.Alarm = True
                    Devices[7].Update(nValue = 1,sValue = Devices[7].sValue)
                    Devices[8].Update(nValue = 4,sValue = "--- ALARME ---")
                    for idx in self.Sirens:
                        DomoticzAPI("type=command&param=switchlight&idx={}&switchcmd=Set Level&level=10".format(
                            idx))  # Levels are 0:OFF, 10:Alarm, 20:siren,30:Flash, 40:Arm, 50:Disarm
                    if self.Telegram:
                        TelegramAPI("ALARME !!!")
                else :
                    if self.Detectionchangedtime + timedelta(seconds = self.Alarmondelay) <= now:
                        Domoticz.Debug("Intrusion Detected and timer On period passed : Alarm ACTIVE !")
                        self.Alarm = True
                        Devices[8].Update(nValue = 4,sValue = "Pas d'identification pendant le temps alloue")
                        Devices[8].Update(nValue = 4,sValue = "ALARME")
                        if self.Telegram:
                            TelegramAPI("Pas d'identification pendant le temps alloue --- ALARME !")
                        if self.Alexa:
                            AlexaAlarmAPI("Attention - Vous ne vous zètes pas identifié. Je déclenche lalarme")
                            time.sleep(5)
                        Devices[7].Update(nValue=1, sValue=Devices[7].sValue)
                        for idx in self.Sirens:
                            DomoticzAPI("type=command&param=switchlight&idx={}&switchcmd=Set Level&level=10".format(idx)) # Levels are 0:OFF, 10:Alarm, 20:siren,30:Flash, 40:Arm, 50:Disarm
                    else:
                        Domoticz.Debug("Intrusion Detected : Siren is INACTIVE but in timer ON period !")
                        for idx in self.Sirens:
                            DomoticzAPI("type=command&param=switchlight&idx={}&switchcmd=Set Level&level=30".format(idx)) # Levels are 0:OFF, 10:Alarm, 20:siren,30:Flash, 40:Arm, 50:Disarm
                        if self.Telegram:
                            TelegramAPI("INTRUSION DETECTEE - IDENTIFICATION REQUISE")
                        if self.Alexa:
                            AlexaAlarmAPI("Veuillez vous identifier")
                            time.sleep(3)
                            if self.AlarmLevel == 1:
                                self.verifPS()
                            elif self.AlarmLevel == 2:
                                self.verifPS()
                                self.verifMS1()
                            else:
                                self.verifPS()
                                self.verifMS1()
                                self.verifMS2()

            elif self.Alarm:
                Domoticz.Debug("Alarm is already ACTIVE !")

        if self.Alarm:
            if self.Detectionchangedtime + timedelta(seconds = (self.Alarmondelay + self.Alarmoffdelay)) <= now:
                # Reset of the zone detection for checking if new intrusion
                Domoticz.Debug("Alarm reset after timer OFF period !")
                self.Alarm = False
                Devices[7].Update(nValue = 0,sValue = Devices[7].sValue)
                Devices[8].Update(nValue = 3,sValue = "RESET - Protection Armee")
                for idx in self.Sirens:
                    DomoticzAPI("type=command&param=switchlight&idx={}&switchcmd=Set Level&level=0".format(idx))  # Levels are 0:OFF, 10:Alarm, 20:siren,30:Flash, 40:Arm, 50:Disarm

                if self.Telegram:
                    TelegramAPI("RESET - Protection Armee")
                if self.Alexa:
                    AlexaAlarmAPI("Reset de lalarme - Protection relancé")
                    # Set lower All Alexa in alarm Group :
                    #cmd = 'sudo /home/pi/script/alexa_remote_control.sh -d Alarme -e vol:40'
                    #Domoticz.Debug("Calling Alexa Alarme API: {}".format(cmd))
                    #os.system(cmd)
                self.Intrusion = False
                Devices[6].Update(nValue = 0,sValue = Devices[6].sValue)
            else:
                Domoticz.Debug("Alarm is ACTIVE but in timer OFF period !")
                if self.Telegram:
                    TelegramAPI("ALARME !!!")
                if self.Alexa:
                    AlexaAlarmAPI("Veuillez vous identifier")
                    time.sleep(3)
                    if self.AlarmLevel == 1:
                        self.verifPS()
                    elif self.AlarmLevel == 2:
                        self.verifPS()
                        self.verifMS1()
                    else:
                        self.verifPS()
                        self.verifMS1()
                        self.verifMS2()

    def getUserVar(self):

        variables = DomoticzAPI("type=command&param=getuservariables")
        if variables:
            # there is a valid response from the API but we do not know if our variable exists yet
            novar = True
            varname = Parameters["Name"] + "-InternalVariables"
            valuestring = ""
            if "result" in variables:
                for variable in variables["result"]:
                    if variable["Name"] == varname:
                        valuestring = variable["Value"]
                        novar = False
                        break
            if novar:
                # create user variable since it does not exist
                self.WriteLog("User Variable {} does not exist. Creation requested".format(varname), "Verbose")

                # check for Domoticz version:
                # there is a breaking change on dzvents_version 2.4.9, API was changed from 'saveuservariable' to 'adduservariable'
                # using 'saveuservariable' on latest versions returns a "status = 'ERR'" error

                # get a status of the actual running Domoticz instance, set the parameter accordigly
                parameter = "saveuservariable"
                domoticzInfo = DomoticzAPI("type=command&param=getversion")
                if domoticzInfo is None:
                    Domoticz.Error("Unable to fetch Domoticz info... unable to determine version")
                else:
                    if domoticzInfo and LooseVersion(domoticzInfo["dzvents_version"]) >= LooseVersion("2.4.9"):
                        self.WriteLog("Use 'adduservariable' instead of 'saveuservariable'", "Verbose")
                        parameter = "adduservariable"

                # actually calling Domoticz API
                DomoticzAPI("type=command&param={}&vname={}&vtype=2&vvalue={}".format(parameter, varname, str(self.InternalsDefaults)))

                self.Internals = self.InternalsDefaults.copy()  # we re-initialize the internal variables
            else:
                try:
                    self.Internals.update(eval(valuestring))
                except:
                    self.Internals = self.InternalsDefaults.copy()
                return
        else:
            Domoticz.Error("Cannot read the uservariable holding the persistent variables")
            self.Internals = self.InternalsDefaults.copy()

    def saveUserVar(self):

        varname = Parameters["Name"] + "-InternalVariables"
        DomoticzAPI("type=command&param=updateuservariable&vname={}&vtype=2&vvalue={}".format(varname, str(self.Internals)))

    def WriteLog(self, message, level="Normal"):

        if self.loglevel == "Verbose" and level == "Verbose":
            Domoticz.Log(message)
        elif level == "Normal":
            Domoticz.Log(message)



global _plugin
_plugin = BasePlugin()


def onStart():
    global _plugin
    _plugin.onStart()


def onStop():
    global _plugin
    _plugin.onStop()


def onCommand(Unit, Command, Level, Color):
    global _plugin
    _plugin.onCommand(Unit, Command, Level, Color)


def onHeartbeat():
    global _plugin
    _plugin.onHeartbeat()


# Plugin utility functions ---------------------------------------------------

def parseCSV(strCSV):

    listvals = []
    for value in strCSV.split(","):
        try:
            val = int(value)
        except:
            pass
        else:
            listvals.append(val)
    return listvals


def DomoticzAPI(APICall):

    resultJson = None
    url = "http://127.0.0.1:8080/json.htm?{}".format(parse.quote(APICall, safe="&="))
    Domoticz.Debug("Calling domoticz API: {}".format(url))
    try:
        req = request.Request(url)
        # if Parameters["Username"] != "":
        #     Domoticz.Debug("Add authentification for user {}".format(Parameters["Username"]))
        #     credentials = ('%s:%s' % (Parameters["Username"], Parameters["Password"]))
        #     encoded_credentials = base64.b64encode(credentials.encode('ascii'))
        #     req.add_header('Authorization', 'Basic %s' % encoded_credentials.decode("ascii"))

        response = request.urlopen(req)
        if response.status == 200:
            resultJson = json.loads(response.read().decode('utf-8'))
            if resultJson["status"] != "OK":
                Domoticz.Error("Domoticz API returned an error: status = {}".format(resultJson["status"]))
                resultJson = None
        else:
            Domoticz.Error("Domoticz API: http error = {}".format(response.status))
    except:
        Domoticz.Error("Error calling '{}'".format(url))
    return resultJson

def TelegramAPI(APICall):

    resultJson = None
    url = "https://api.telegram.org/bot981531159:AAFPt2yI9BhfD2XdI3mUIgIdD2Jt_3A6kOw/sendMessage?chat_id={}&text={}".format(Parameters["Username"], parse.quote(APICall, safe="&="))
    Domoticz.Debug("Calling Telegram API: {}".format(url))
    try:
        req = request.Request(url)

        response = request.urlopen(req)
        if response.status == 200:
            resultJson = json.loads(response.read().decode('utf-8'))
            if resultJson["status"] != "true":
                Domoticz.Error("Telegram API returned an error: status = {}".format(resultJson["ok"]))
                resultJson = None
        else:
            Domoticz.Error("Telegram API: http error = {}".format(response.status))
    except:
        Domoticz.Debug("Error calling '{}'".format(url))
    return resultJson

def AlexaAPI(APICall):
    # Check last alexa for knowing where speaking :
    cmd = 'sudo /home/pi/script/alexa_remote_control.sh -lastalexa {} cut -d"=" -f1'.format("|")
    output = sp.getoutput(cmd)
    Domoticz.Debug("Last alexa speaking : {}".format(output))

    #time.sleep(2)
    #if not self.VoiceLevelNormal :
    #cmd = 'sudo /home/pi/script/alexa_remote_control.sh -d Alarme -e vol:40'
    #Domoticz.Debug("Calling Alexa API: {}".format(cmd))
    #os.system(cmd)
    #self.VoiceLevelNormal = True

    time.sleep(1)

    cmd = 'sudo /home/pi/script/alexa_remote_control.sh -d {} -e speak:"{}"'.format(output, APICall)
    Domoticz.Debug("Calling Alexa API: {}".format(cmd))
    os.system(cmd)

def AlexaAlarmAPI(APICall):

    #if not self.VoiceAlarmLevelMax :
    #cmd = 'sudo /home/pi/script/alexa_remote_control.sh -d Alarme -e vol:100'
    #Domoticz.Debug("Calling Alexa Alarme API: {}".format(cmd))
    #os.system(cmd)
    # self.VoiceAlarmLevelMax = True

    #time.sleep(2)

    cmd = 'sudo /home/pi/script/alexa_remote_control.sh -d Alarme -e speak:"{}"'.format(APICall)
    Domoticz.Debug("Calling Alexa Alarme API: {}".format(cmd))
    os.system(cmd)

def CheckParam(name, value, default):

    try:
        param = int(value)
    except ValueError:
        param = default
        Domoticz.Error("Parameter '{}' has an invalid value of '{}' ! defaut of '{}' is instead used.".format(name, value, default))
    return param


# Generic helper functions
def DumpConfigToLog():
    for x in Parameters:
        if Parameters[x] != "":
            Domoticz.Debug("'" + x + "':'" + str(Parameters[x]) + "'")
    Domoticz.Debug("Device count: " + str(len(Devices)))
    for x in Devices:
        Domoticz.Debug("Device:           " + str(x) + " - " + str(Devices[x]))
        Domoticz.Debug("Device ID:       '" + str(Devices[x].ID) + "'")
        Domoticz.Debug("Device Name:     '" + Devices[x].Name + "'")
        Domoticz.Debug("Device nValue:    " + str(Devices[x].nValue))
        Domoticz.Debug("Device sValue:   '" + Devices[x].sValue + "'")
        Domoticz.Debug("Device LastLevel: " + str(Devices[x].LastLevel))
    return

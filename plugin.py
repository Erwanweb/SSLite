"""
CASA-IA Security system zone python plugin for Domoticz
Author: Erwanweb,
Version:    0.0.1: alpha
            0.0.2: beta
"""
"""
<plugin key="SSLite" name="AC Security system LITE" author="Erwanweb" version="0.0.2" externallink="https://github.com/Erwanweb/BoilerCLite.git">
    <description>
        <h2>Security system Lite for CASA-IA</h2><br/>
        Easily control security zone<br/>
        <h3>Set-up and Configuration</h3>
    </description>
    <params>
        <param field="Address" label="Domoticz IP Address" width="200px" required="true" default="127.0.0.1"/>
        <param field="Port" label="Port" width="40px" required="true" default="8080"/>
        <param field="Username" label="Username" width="200px" required="false" default=""/>
        <param field="Password" label="Password" width="200px" required="false" default=""/>
        <param field="Mode1" label="Perimetral door/window Sensors (csv list of idx)" width="200px" required="false" default=""/>
        <param field="Mode2" label="Sirenes (csv list of idx)" width="200px" required="false" default=""/>
        <param field="Mode3" label="Night zone MS Sensors (csv list of idx)" width="200px" required="false" default=""/>
        <param field="Mode4" label="Rest of MS Sensors (csv list of idx)" width="200px" required="true" default=""/>
        <param field="Mode5" label="Arming on delay, Detection delay, Alarm On delay, Alarm Off delay (all in seconds)" width="200px" required="true" default="30,0,0,90"/>
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
        self.Alarmondelay = 0
        self.Alarmoffdelay = 90
        self.DTPerimetral = []
        self.DTNightAlarm = []
        self.DTNormaltAlarm = []
        self.NightNewDetection = False
        self.NightDetection = False
        self.NormalNewDetection = False
        self.NormalDetection = False
        self.Intrusion = False
        self.Alarm = False
        self.Armingtempo = datetime.now()
        self.Perimetraltempo = datetime.now()
        self.NightAlarmtempo = datetime.now()
        self.NightDetectiontempo = datetime.now()
        self.NormalAlarmtempo = datetime.now()
        self.NormalDetectiontempo = datetime.now()
        self.Detectionchangedtime = datetime.now()
        self.loglevel = None
        self.statussupported = True
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
                       "LevelNames":"Not Ready|Off|Perimetral|Night|Total",
                       "LevelOffHidden":"true",
                       "SelectorStyle":"0"}
            Domoticz.Device(Name = "Alarm Control",Unit = 1,TypeName = "Selector Switch",Switchtype = 18,Image = 9,
                            Options = Options,Used = 1).Create()
            devicecreated.append(deviceparam(1,0,"10"))  # default is Off
        if 2 not in Devices:
            Domoticz.Device(Name="Surveillance Armed", Unit=2, TypeName="Switch", Image=9, Used=1).Create()
            devicecreated.append(deviceparam(2, 0, ""))  # default is Off
        if 3 not in Devices:
            Domoticz.Device(Name="Perimetral Detection", Unit=3, TypeName="Switch", Image=9, Used=1).Create()
            devicecreated.append(deviceparam(3, 0, ""))  # default is Off
        if 4 not in Devices:
            Domoticz.Device(Name="Motion Detection", Unit=4, TypeName="Switch", Image=9, Used=1).Create()
            devicecreated.append(deviceparam(4, 0, ""))  # default is Off
        if 5 not in Devices:
            Domoticz.Device(Name="Intrusion Detected", Unit=5, TypeName="Switch", Image=13, Used=1).Create()
            devicecreated.append(deviceparam(5, 0, ""))  # default is Off
        if 6 not in Devices:
            Domoticz.Device(Name="Alarm", Unit=6, TypeName="Switch", Image=13, Used=1).Create()
            devicecreated.append(deviceparam(6, 0, ""))  # default is Off

        # if any device has been created in onStart(), now is time to update its defaults
        for device in devicecreated:
            Devices[device.unit].Update(nValue=device.nvalue, sValue=device.svalue)

        # build lists of alarm sensors
        self.DTPerimetral = parseCSV(Parameters["Mode1"])
        Domoticz.Debug("Perimetral Sensors = {}".format(self.DTPerimetral))
        self.DTNightAlarm = parseCSV(Parameters["Mode3"])
        Domoticz.Debug("Night Motion Sensors = {}".format(self.DTNightAlarm))
        self.DTNormalAlarm = parseCSV(Parameters["Mode4"])
        Domoticz.Debug("Normal Motion Sensors = {}".format(self.DTNormalAlarm))

        # splits additional parameters
        params = parseCSV(Parameters["Mode5"])
        if len(params) == 4:
            self.Armingondelay = CheckParam("delay arming validation)",params[0],30)
            self.Detectiondelay = CheckParam("delay before detection validation)",params[1],0)
            self.Alarmondelay = CheckParam("Alarm On Delay",params[2],30)
            self.Alarmoffdelay = CheckParam("Alarm Off Delay",params[3],60)

        else:
            Domoticz.Error("Error reading Mode5 parameters")



    def onStop(self):

        Domoticz.Debugging(0)


    def onCommand(self, Unit, Command, Level, Color):

        Domoticz.Debug("onCommand called for Unit {}: Command '{}', Level: {}".format(Unit, Command, Level))

        now = datetime.now()

        if (Unit == 1):
            if (Devices[1].nValue == 10):
                Domoticz.Debug("Switching Surveillance Off and so alarm Off !")
                self.NightNewDetection = False
                self.NightDetection = False
                self.NormalNewDetection = False
                self.NormalDetection = False
                self.Intrusion = False
                self.Alarm = False
                Devices[2].Update(nValue = 0,sValue = Devices[2].sValue)
                Devices[3].Update(nValue = 0,sValue = Devices[3].sValue)
                Devices[4].Update(nValue = 0,sValue = Devices[4].sValue)
                Devices[5].Update(nValue = 0,sValue = Devices[5].sValue)
                Devices[6].Update(nValue = 0,sValue = Devices[6].sValue)
            if (Devices[1].nValue >= 20):
                self.Armingtempo = datetime.now()


    def onHeartbeat(self):

        # fool proof checking....
        if not all(device in Devices for device in (1,2,3,4,5,6)):
            Domoticz.Error("one or more devices required by the plugin is/are missing, please check domoticz device creation settings and restart !")
            return

        self.PerimetralDetection() # checking in all time if perimetral is ok, or for alarm, or for arming possibility,

        if (Devices[1].nValue <= 10):  # Surveillance is off but we check if perimetral is ok, if not, unable to turn on protection
            if Devices[3].nValue == 0:
                Devices[1].Update(nValue = 10,sValue = Devices[2].sValue)
            else :
                Devices[1].Update(nValue = 0,sValue = Devices[2].sValue)

        if (Devices[1].nValue <= 10):  # Surveillance is off
            Domoticz.Log("Surveillance desactived...")
            if self.Alarm:  # Surveillance setting was just changed so we kill the surveillance of the zone and stop the eventual alarm
                self.NightNewDetection = False
                self.NightDetection = False
                self.NormalNewDetection = False
                self.NormalDetection = False
                self.Intrusion = False
                self.Alarm = False
                Devices[2].Update(nValue = 0,sValue = Devices[2].sValue)
                Devices[3].Update(nValue = 0,sValue = Devices[3].sValue)
                Devices[4].Update(nValue = 0,sValue = Devices[4].sValue)
                Devices[5].Update(nValue = 0,sValue = Devices[3].sValue)
                Devices[6].Update(nValue = 0,sValue = Devices[4].sValue)

        else: # At Mini Perimetral Surveillance is on
            if self.Armingtempo + timedelta(seconds = self.Armingondelay) <= now:
                Devices[2].Update(nValue = 1,sValue = Devices[2].sValue)
                Domoticz.Log("Arming on delay passed - Perimetral Surveillance is actived...")
            else :
                Domoticz.Log("Alarm Armed but in timer ON period !")
                Devices[2].Update(nValue = 0,sValue = Devices[2].sValue)
                Devices[3].Update(nValue = 0,sValue = Devices[3].sValue)
                Devices[4].Update(nValue = 0,sValue = Devices[4].sValue)
                Devices[5].Update(nValue = 0,sValue = Devices[3].sValue)
                Devices[6].Update(nValue = 0,sValue = Devices[4].sValue)

            if Devices[2].nValue == 1:
                self.AlarmDetection()
                if (Devices[1].nValue == 30):  # Night Surveillance is on
                    Domoticz.Log("Night Surveillance is actived...")
                    self.NightMotionDetection()

                if (Devices[1].nValue == 40):  # Total Surveillance is on
                    Domoticz.Log("Total Surveillance is actived...")
                    self.NightMotionDetection()
                    self.NormalMotionDetection()


    def PerimetralDetection(self):

        now = datetime.now()

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
                        Domoticz.Debug("Perimetral DT switch {} currently is '{}'".format(idx,device["Status"]))
                        if device["Status"] == "On":
                            self.Perimetraltempo = datetime.now()

                    else:
                        Domoticz.Error("Device with idx={} does not seem to be a perimetral DT switch !".format(idx))

        if self.Perimetraltempo + timedelta(seconds = 15) >= now:
            Domoticz.Debug("At mini 1 perimetral DT switch is ON or was ON in the past 15 seconds...")
            if Devices[3].nValue == 0:
                Devices[3].Update(nValue = 1,sValue = Devices[8].sValue)
        else:
            if Devices[3].nValue == 1:
                Devices[3].Update(nValue = 0,sValue = Devices[8].sValue)

        if (Devices[1].nValue >= 20):  # Surveillance is on
            if Devices[2].nValue == 1:
                if Devices[3].nValue == 1:
                    if Devices[5].nValue == 1:
                        Domoticz.Log("There is intrusion but already registred...")
                    else:
                        Domoticz.Log("New intrusion...")
                        Devices[5].Update(nValue = 1,sValue = Devices[5].sValue)
                        self.Intrusion = True
                        self.Detectionchangedtime = datetime.now()



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
                        Domoticz.Debug("DT switch {} currently is '{}'".format(idx,device["Status"]))
                        if device["Status"] == "On":
                            self.NightAlarmtempo = datetime.now()

                    else:
                        Domoticz.Error("Device with idx={} does not seem to be a DT !".format(idx))

        # fool proof checking....
        if len(NightAlarmDT) == 0:
            Domoticz.Error("none of the devices in the 'MS or door/window sensor' parameter is a switch... no action !")
            self.NewDetection = False
            self.Detection = False
            self.Alarm = False
            Devices[1].Update(nValue = 0,sValue = Devices[1].sValue)
            Devices[2].Update(nValue = 0,sValue = Devices[2].sValue)
            Devices[3].Update(nValue = 0,sValue = Devices[3].sValue)
            Devices[4].Update(nValue = 0,sValue = Devices[4].sValue)
            Devices[5].Update(nValue = 0,sValue = Devices[3].sValue)
            Devices[6].Update(nValue = 0,sValue = Devices[4].sValue)
            return

        if self.NightAlarmtempo + timedelta(seconds = 15) >= now:
            self.NightNewDetection = True
            Domoticz.Log("At mini 1 Alarm sensor is ON or Was ON in the past 15 seconds...")
        else:
            self.NightNewDetection = False
            Domoticz.Log("No Detection, All OK, No Alarm !")

        if self.NightNewDetection:
            if Devices[4].nValue == 1:
                Domoticz.Log("There is detection but already registred...")
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
            if Devices[5].nValue == 1:
                Domoticz.Log("There is intrusion but already registred...")
            else:
                if self.Detectiondelay == 0:
                    Domoticz.Log("New intrusion...")
                    Devices[5].Update(nValue = 1,sValue = Devices[5].sValue)
                    self.Intrusion = True
                    self.Detectionchangedtime = datetime.now()
                else :
                    if self.Detectiontempo + timedelta(seconds = self.Detectiondelay) <= now:
                        Domoticz.Log("New intrusion...")
                        Devices[5].Update(nValue = 1,sValue = Devices[5].sValue)
                        self.Intrusion = True
                        self.Detectionchangedtime = datetime.now()

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
                        Domoticz.Debug("DT switch {} currently is '{}'".format(idx,device["Status"]))
                        if device["Status"] == "On":
                            self.NormalAlarmtempo = datetime.now()

                    else:
                        Domoticz.Error("Device with idx={} does not seem to be a DT !".format(idx))

        # fool proof checking....
        if len(NormalAlarmDT) == 0:
            Domoticz.Error("none of the devices in the 'MS or door/window sensor' parameter is a switch... no action !")
            self.NewDetection = False
            self.Detection = False
            self.Alarm = False
            Devices[1].Update(nValue = 0,sValue = Devices[1].sValue)
            Devices[2].Update(nValue = 0,sValue = Devices[2].sValue)
            Devices[3].Update(nValue = 0,sValue = Devices[3].sValue)
            Devices[4].Update(nValue = 0,sValue = Devices[4].sValue)
            Devices[5].Update(nValue = 0,sValue = Devices[3].sValue)
            Devices[6].Update(nValue = 0,sValue = Devices[4].sValue)
            return

        if self.NormalAlarmtempo + timedelta(seconds = 15) >= now:
            self.NormalNewDetection = True
            Domoticz.Log("At mini 1 Alarm sensor is ON or Was ON in the past 15 seconds...")
        else:
            self.NormalNewDetection = False
            Domoticz.Log("No Detection, All OK, No Alarm !")

        if self.NormalNewDetection:
            if Devices[4].nValue == 1:
                Domoticz.Log("There is detection but already registred...")
            else:
                Domoticz.Log("New Detection...")
                Devices[4].Update(nValue = 1,sValue = Devices[4].sValue)
                self.NormalDetection = True
                self.NormalDetectiontempo = datetime.now()
        else:
            if Devices[4].nValue == 0:
                Domoticz.Debug("No detection, detection already OFF...")
            else:
                Domoticz.Debug("No detection in detection delay...")
                Devices[4].Update(nValue = 0,sValue = Devices[4].sValue)
                self.NormalDetection = False

        if self.NormalDetection:
            if Devices[5].nValue == 1:
                Domoticz.Log("There is intrusion but already registred...")
            else:
                if self.Detectiondelay == 0:
                    Domoticz.Log("New intrusion...")
                    Devices[5].Update(nValue = 1,sValue = Devices[5].sValue)
                    self.Intrusion = True
                    self.Detectionchangedtime = datetime.now()
                else :
                    if self.Detectiontempo + timedelta(seconds = self.Detectiondelay) <= now:
                        Domoticz.Log("New intrusion...")
                        Devices[5].Update(nValue = 1,sValue = Devices[5].sValue)
                        self.Intrusion = True
                        self.Detectionchangedtime = datetime.now()

    def AlarmDetection(self):

        if self.Intrusion:
            if not self.Alarm:
                if self.Alarmondelay == 0:
                    Domoticz.Log("Intrusion Detected and alarm setted as imediate : Alarm ACTIVE !")
                    self.Alarm = True
                    Devices[6].Update(nValue = 1,sValue = Devices[6].sValue)
                else :
                    if self.Detectionchangedtime + timedelta(seconds = self.Alarmondelay) <= now:
                        Domoticz.Log("Intrusion Detected and timer On period passed : Alarm ACTIVE !")
                        self.Alarm = True
                        Devices[6].Update(nValue = 1,sValue = Devices[6].sValue)
                    else:
                        Domoticz.Log("Intrusion Detected : Alarm is INACTIVE but in timer ON period !")
            elif self.Alarm:
                Domoticz.Log("Alarm is already ACTIVE !")

        if self.Alarm:
            if self.Detectionchangedtime + timedelta(seconds = (self.Alarmondelay + self.Alarmoffdelay)) <= now:
                # Reset of the zone detection for checking if new intrusion
                Domoticz.Log("Alarm reset after timer OFF period !")
                self.Alarm = False
                Devices[6].Update(nValue = 0,sValue = Devices[6].sValue)
                self.Intrusion = False
                Devices[5].Update(nValue = 0,sValue = Devices[5].sValue)

            else:
                Domoticz.Log("Alarm is ACTIVE but in timer OFF period !")

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
    url = "http://{}:{}/json.htm?{}".format(Parameters["Address"], Parameters["Port"], parse.quote(APICall, safe="&="))
    Domoticz.Debug("Calling domoticz API: {}".format(url))
    try:
        req = request.Request(url)
        if Parameters["Username"] != "":
            Domoticz.Debug("Add authentification for user {}".format(Parameters["Username"]))
            credentials = ('%s:%s' % (Parameters["Username"], Parameters["Password"]))
            encoded_credentials = base64.b64encode(credentials.encode('ascii'))
            req.add_header('Authorization', 'Basic %s' % encoded_credentials.decode("ascii"))

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

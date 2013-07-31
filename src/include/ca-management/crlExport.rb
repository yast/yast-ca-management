# encoding: utf-8

# ***************************************************************************
#
# Copyright (c) 2004 - 2012 Novell, Inc.
# All Rights Reserved.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of version 2 of the GNU General Public License as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.   See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, contact Novell, Inc.
#
# To contact Novell about this file by physical or electronic mail,
# you may find current contact information at www.novell.com
#
# ***************************************************************************
#
# File:
#   crlExport.ycp
#
# Module:
#   CA Management
#
# Summary:
#   Export a CRL to a local file or an LDAP directory.
#   Possibility to setup a cron job to do this automatically.
#
# Authors:
#   J. Daniel Schmidt <jdsn@suse.de>
#
# $Id: crlExport.ycp 1 2007-11-20 12:15:18Z jdsn $
#
# Export a CRL for a selected CA
#
module Yast
  module CaManagementCrlExportInclude
    def initialize_ca_management_crlExport(include_target)
      Yast.import "UI"

      textdomain "ca-management"

      Yast.import "CaMgm"
      Yast.import "Wizard"
      Yast.import "Label"
      Yast.import "Popup"
      Yast.import "YaPI::CaManagement"
      Yast.import "String"
      Yast.include include_target, "ca-management/util.rb"
      Yast.include include_target, "ca-management/new_cert_callbacks.rb"

      @uiInfo = UI.GetDisplayInfo
      @textmode = Ops.get_boolean(@uiInfo, "TextMode")

      @hspace = Convert.convert(
        @textmode ? 4 : 3,
        :from => "integer",
        :to   => "float"
      )
      @vspace = Convert.convert(
        @textmode ? 0 : 0.5,
        :from => "integer",
        :to   => "float"
      ) # less spacing (bnc#446137)
      @seenSecurityInfo = false

      # here are our settings for the CRL of this CA
      @periodic = false # default off
      @file_active = true # default on
      @ldap_active = false # default off
      @fileformat = :ffpem # default is pem
      @crlfile = "" # is set from inside the export function
      @intervalAtHour = 0
      @intervalHours = 0
      @ldapCred = {
        "hostname" => "",
        "port"     => "",
        "dn"       => "",
        "binddn"   => "",
        "password" => ""
      }


      @crlConfFormat = {
        "options"  => [
          "line_can_continue",
          "global_values",
          "join_multiline",
          "comments_last",
          "flat"
        ],
        "comments" => ["^[ \t]*#.*$", "^[ \t]*$"],
        "params"   => [
          { "match" => ["([a-zA-Z0-9_-]+)[ \t]*=[ \t]*([^ \t]*)", "%s = %s"] }
        ]
      }
    end

    def showSecurityInfo
      Popup.LongText(
        # Translators: window caption
        _("Security Information"),
        # Translators: long help text - security information
        RichText(
          _(
            "Warning!<br>Activating the automatic creation and export of a CRL will write the CA password to a configuration file on disk. The password will be stored there in plain text as it is needed to create a CRL. The file will only be readable for the root user."
          )
        ),
        50,
        12
      )
      @seenSecurityInfo = true

      nil
    end


    def updateEnabled
      @periodic = Convert.to_boolean(
        UI.QueryWidget(Id(:mode_periodically), :Value)
      )
      @file_active = Convert.to_boolean(UI.QueryWidget(Id(:exportFile), :Value))
      @ldap_active = Convert.to_boolean(UI.QueryWidget(Id(:exportLDAP), :Value))
      UI.ChangeWidget(Id(:periodicInterval), :Enabled, @periodic)
      UI.ChangeWidget(Id(:fileSettings), :Enabled, @file_active)
      UI.ChangeWidget(Id(:ldapSettings), :Enabled, @ldap_active)
      showSecurityInfo if @periodic && !@seenSecurityInfo

      nil
    end



    def setSettings
      # write settings to the UI
      UI.ChangeWidget(Id(:mode_periodically), :Value, @periodic)
      UI.ChangeWidget(Id(:periodicInterval), :Enabled, @periodic)
      UI.ChangeWidget(Id(:interval_athour), :Value, @intervalAtHour)
      UI.ChangeWidget(Id(:interval_hours), :Value, @intervalHours)
      UI.ChangeWidget(
        Id(:atHourSetting),
        :Enabled,
        @intervalHours == 24 ? true : false
      )

      UI.ChangeWidget(Id(:exportFile), :Value, @file_active)
      UI.ChangeWidget(Id(:exportLDAP), :Value, @ldap_active)

      UI.ChangeWidget(Id(:ffpem), :Value, @fileformat == :ffpem ? true : false)
      UI.ChangeWidget(Id(:ffder), :Value, @fileformat == :ffder ? true : false)
      UI.ChangeWidget(Id(:crlfile), :Value, @crlfile)

      UI.ChangeWidget(Id(:hostname), :Value, Ops.get(@ldapCred, "hostname", ""))
      UI.ChangeWidget(Id(:port), :Value, Ops.get(@ldapCred, "port", ""))
      UI.ChangeWidget(Id(:dn), :Value, Ops.get(@ldapCred, "dn", ""))
      UI.ChangeWidget(Id(:binddn), :Value, Ops.get(@ldapCred, "binddn", ""))
      UI.ChangeWidget(
        Id(:ldapPassword),
        :Value,
        Ops.get(@ldapCred, "password", "")
      )

      nil
    end



    def cleanLdapCred
      # cleanup ldap credetials hash ... remove nil values
      Builtins.foreach(@ldapCred) do |key, val|
        Ops.set(@ldapCred, key, "") if val == nil
      end

      nil
    end


    def readSettings(ca)
      crlConf = Builtins.sformat(
        "/var/lib/CAM/%1/exportcrl.conf",
        Builtins.deletechars(ca, " ")
      )
      if SCR.Execute(
          path(".target.bash"),
          Builtins.sformat("[ -f  %1  ]", String.Quote(crlConf))
        ) == 0
        SCR.RegisterAgent(
          path(".temp_crlexport_agent"),
          term(:ag_ini, term(:IniAgent, crlConf, @crlConfFormat))
        )

        @periodic = SCR.Read(path(".temp_crlexport_agent.periodic")) == "true" ? true : false
        @seenSecurityInfo = true if @periodic
        getAtHour = Builtins.tointeger(
          Convert.to_string(
            SCR.Read(path(".temp_crlexport_agent.interval_athour"))
          )
        )
        @intervalAtHour = getAtHour != nil ? getAtHour : @intervalAtHour
        getHours = Builtins.tointeger(
          Convert.to_string(
            SCR.Read(path(".temp_crlexport_agent.interval_hours"))
          )
        )
        @intervalHours = getHours != nil ? getHours : @intervalHours
        @intervalAtHour = 0 if @intervalHours != 24

        @file_active = SCR.Read(path(".temp_crlexport_agent.export_file")) == "true" ? true : false
        @ldap_active = SCR.Read(path(".temp_crlexport_agent.export_ldap")) == "true" ? true : false
        getCrlfile = Convert.to_string(
          SCR.Read(path(".temp_crlexport_agent.crlfilename"))
        )
        @crlfile = getCrlfile if getCrlfile != nil && getCrlfile != ""
        @fileformat = SCR.Read(path(".temp_crlexport_agent.crlfileformat")) == "der" ? :ffder : :ffpem
        Ops.set(
          @ldapCred,
          "hostname",
          Convert.to_string(
            SCR.Read(path(".temp_crlexport_agent.ldap_hostname"))
          )
        )
        Ops.set(
          @ldapCred,
          "port",
          Convert.to_string(SCR.Read(path(".temp_crlexport_agent.ldap_port")))
        )
        Ops.set(
          @ldapCred,
          "dn",
          Convert.to_string(SCR.Read(path(".temp_crlexport_agent.ldap_dn")))
        )
        Ops.set(
          @ldapCred,
          "binddn",
          Convert.to_string(SCR.Read(path(".temp_crlexport_agent.ldap_binddn")))
        )
        Ops.set(
          @ldapCred,
          "password",
          Convert.to_string(
            SCR.Read(path(".temp_crlexport_agent.ldap_password"))
          )
        )
        @ldapCred = {} if !@ldap_active
        cleanLdapCred

        SCR.UnregisterAgent(path(".temp_crlexport_agent"))
        Builtins.y2milestone(
          "Found config file for automatic CRL export of CA %1  and read settings.",
          ca
        )
      else
        Builtins.y2milestone(
          "No config file found for automatic CRL export of CA %1",
          ca
        )
      end

      nil
    end



    def writeSettings(ca)
      crlConf = Builtins.sformat(
        "/var/lib/CAM/%1/exportcrl.conf",
        Builtins.deletechars(ca, " ")
      )
      if !(SCR.Execute(
          path(".target.bash"),
          Builtins.sformat("[ -f  %1  ]", String.Quote(crlConf))
        ) == 0)
        SCR.Execute(
          path(".target.bash"),
          Builtins.sformat("umask 0077  &&  touch  %1", String.Quote(crlConf))
        )
      end

      SCR.RegisterAgent(
        path(".temp_crlexport_agent"),
        term(:ag_ini, term(:IniAgent, crlConf, @crlConfFormat))
      )

      SCR.Write(path(".temp_crlexport_agent.caname"), ca)
      SCR.Write(
        path(".temp_crlexport_agent.periodic"),
        @periodic ? "true" : "false"
      )
      SCR.Write(
        path(".temp_crlexport_agent.capassword"),
        @periodic ? getPassword(ca) : ""
      )

      SCR.Write(
        path(".temp_crlexport_agent.interval_athour"),
        @intervalHours == 24 ? "0" : Builtins.sformat("%1", @intervalAtHour)
      )
      SCR.Write(
        path(".temp_crlexport_agent.interval_hours"),
        Builtins.sformat("%1", @intervalHours)
      )

      SCR.Write(
        path(".temp_crlexport_agent.export_file"),
        @file_active == true ? "true" : "false"
      )
      SCR.Write(
        path(".temp_crlexport_agent.export_ldap"),
        @ldap_active == true ? "true" : "false"
      )

      SCR.Write(
        path(".temp_crlexport_agent.crlfilename"),
        @file_active ? @crlfile : ""
      )
      SCR.Write(
        path(".temp_crlexport_agent.crlfileformat"),
        @fileformat == :ffder ? "der" : "pem"
      )

      @ldapCred = {} if !@ldap_active
      SCR.Write(
        path(".temp_crlexport_agent.ldap_hostname"),
        Ops.get(@ldapCred, "hostname", "")
      )
      SCR.Write(
        path(".temp_crlexport_agent.ldap_port"),
        Ops.get(@ldapCred, "port", "")
      )
      SCR.Write(
        path(".temp_crlexport_agent.ldap_dn"),
        Ops.get(@ldapCred, "dn", "")
      )
      SCR.Write(
        path(".temp_crlexport_agent.ldap_binddn"),
        Ops.get(@ldapCred, "binddn", "")
      )
      SCR.Write(
        path(".temp_crlexport_agent.ldap_password"),
        Ops.get(@ldapCred, "password", "")
      )

      SCR.UnregisterAgent(path(".temp_crlexport_agent"))

      Builtins.y2milestone(
        "Written settings for automatic CRL export to conf file %1",
        crlConf
      )

      nil
    end


    # Editing CRL defaults of a selected CA
    # @param selected CA
    def exportCRL(ca)
      ret = YaPI::CaManagement.ReadCRLDefaults(
        { "caName" => ca, "caPasswd" => getPassword(ca) }
      )
      Builtins.y2milestone(
        "ReadCRLDefaults(%1) return %2",
        { "caName" => ca },
        ret
      )

      caption = _("Export CRL")
      # this default can only be set inside this function
      @crlfile = Builtins.sformat(
        "/var/lib/CAM/%1/crl/crl.pem",
        Builtins.deletechars(ca, " ")
      )


      help_para1 = Builtins.sformat("<p><b>%1</b></p>", caption)
      help_para2 = _(
        "<p>Export the CRL of this CA once by selecting <b>Export once</b>.</p>"
      )
      help_para3 = _(
        "<p>To set up a repeated recreation of the CRL, select <b>Repeated recreation and export</b>. In this case, set the interval for the recreation in <b>Periodic interval</b>. If you set the interval to 24 hours, you can additionally select the hour for the export. Make sure you read and understand the <b>Security Information</b>.</p>"
      )
      help_para4 = _(
        "<p>You can activate an export of the CRL to a local file or to an LDAP server or both. Set up the respective parameters in <b>Export to local file</b> and <b>Export to LDAP</b>.</p>"
      )

      helptext = Ops.add(
        Ops.add(Ops.add(help_para1, help_para2), help_para3),
        help_para4
      )

      cradiobuttons = VBox(
        RadioButtonGroup(
          Id(:export_mode),
          VBox(
            Left(
              RadioButton(Id(:mode_once), Opt(:notify), _("Export once"), true)
            ),
            Left(
              RadioButton(
                Id(:mode_periodically),
                Opt(:notify),
                _("Repeated recreation and export")
              )
            )
          )
        )
      )

      # fix space issue (bnc#446137)
      cldapsettings = HBox(
        Id(:ldapSettings),
        Top(
          VBox(
            TextEntry(Id(:hostname), _("&Host Name:"), ""),
            TextEntry(Id(:port), _("&Port:"), ""),
            TextEntry(Id(:dn), _("&DN:"))
          )
        ),
        Top(
          VBox(
            TextEntry(Id(:binddn), _("&Bind DN:"), ""),
            Password(Id(:ldapPassword), Opt(:hstretch), _("Pass&word"))
          )
        )
      )

      cfilesettings = VBox(
        Id(:fileSettings),
        HBox(
          TextEntry(Id(:crlfile), _("Save &as"), @crlfile),
          VBox(VSpacing(1), PushButton(Id(:askFile), Label.BrowseButton))
        ),
        Left(
          RadioButtonGroup(
            Id(:fileformat),
            HBox(
              Label(_("Export Format")),
              RadioButton(Id(:ffpem), Opt(:notify), _("PEM Format"), true),
              RadioButton(Id(:ffder), Opt(:notify), _("DER Format"))
            )
          )
        )
      )

      cinterval = Left(
        Id(:periodicInterval),
        HBox(
          VBox(Label(_("Periodic interval")), VSpacing(1)),
          HSpacing(3),
          #`HSquash( `IntField( `id(`interval_days), "&days", 0, 100, 30 )),
          # Translators: this is used to express a setting of  "every XX hour(s)"
          Label(_("every")),
          # Translators: this is used to express a setting of  "every XX hour(s)"
          HSquash(
            IntField(
              Id(:interval_hours),
              Opt(:notify),
              _("&hour(s)"),
              1,
              24,
              12
            )
          ), # (bnc#446137)
          # Translators: in case "every XX hour(s)" is set to 24, the user can set "at XX o'clock"
          HBox(
            Id(:atHourSetting),
            Label(_("at")),
            # Translators: in case "every XX hour(s)" is set to 24, the user can set "at XX o'clock"
            HSquash(IntField(Id(:interval_athour), _("&o'clock"), 0, 23, 3))
          ), # (bnc#446137)
          HSpacing(3),
          VBox(
            VSpacing(1),
            PushButton(Id(:securityInfo), _("&Security Information"))
          )
        )
      )

      contents = HBox(
        HSpacing(1),
        VBox(
          Left(Heading(Ops.add(_("CA Name: "), CaMgm.currentCA))),
          cradiobuttons,
          HBox(
            HSpacing(3),
            VBox(
              VSpacing(@vspace),
              Left(
                CheckBox(
                  Id(:exportFile),
                  Opt(:notify),
                  _("Export to file"),
                  true
                )
              ),
              HBox(HSpacing(@hspace), cfilesettings),
              VSpacing(@vspace),
              Left(
                CheckBox(
                  Id(:exportLDAP),
                  Opt(:notify),
                  _("Export to LDAP"),
                  false
                )
              ),
              HBox(HSpacing(@hspace), cldapsettings),
              VSpacing(@vspace),
              cinterval
            )
          )
        ),
        HSpacing(1)
      )

      Wizard.CreateDialog
      Wizard.SetContentsButtons(
        _("Export CRL"),
        contents,
        helptext,
        Label.BackButton,
        Label.OKButton
      )
      Wizard.DisableBackButton

      # fill UI with settings
      readSettings(ca) # read conf file if exists
      setSettings # push data to UI
      updateEnabled # gray out or ungray UI elements

      ui = nil
      begin
        ui = Convert.to_symbol(UI.UserInput)

        add_advanced_issuer_alt_name = "test" if ui == :add
        if ui == :askFile
          fformat = "*.pem"
          fformat = "*.der" if @fileformat == :ffder
          newcrlfile = UI.AskForSaveFileName(@crlfile, fformat, _("Save as"))
          @crlfile = newcrlfile if newcrlfile != nil && newcrlfile != ""
        end
        if Builtins.contains(
            [:mode_once, :mode_periodically, :exportFile, :exportLDAP],
            ui
          )
          updateEnabled
        end
        if ui == :ffpem || ui == :ffder
          @fileformat = Convert.to_symbol(
            UI.QueryWidget(Id(:fileformat), :Value)
          )
          formatstr = ""
          outputstr = ""
          if @fileformat == :ffpem
            formatstr = "^(.*.)der$"
            outputstr = "\\1pem"
          elsif @fileformat == :ffder
            formatstr = "^(.*.)pem$"
            outputstr = "\\1der"
          end
          newfile = Builtins.regexpsub(@crlfile, formatstr, outputstr)
          @crlfile = newfile if newfile != nil && newfile != ""
        end
        if ui == :interval_hours || ui == :interval_athour
          @intervalHours = Convert.to_integer(
            UI.QueryWidget(Id(:interval_hours), :Value)
          )
          @intervalAtHour = Convert.to_integer(
            UI.QueryWidget(Id(:interval_athour), :Value)
          )
        end
        showSecurityInfo if ui == :securityInfo
        if ui == :next
          updateEnabled
          @fileformat = Convert.to_symbol(
            UI.QueryWidget(Id(:fileformat), :Value)
          )
          @crlfile = Convert.to_string(UI.QueryWidget(Id(:crlfile), :Value))
          @intervalAtHour = Convert.to_integer(
            UI.QueryWidget(Id(:interval_athour), :Value)
          )
          @intervalHours = Convert.to_integer(
            UI.QueryWidget(Id(:interval_hours), :Value)
          )
          Ops.set(
            @ldapCred,
            "hostname",
            Convert.to_string(UI.QueryWidget(Id(:hostname), :Value))
          )
          Ops.set(
            @ldapCred,
            "port",
            Convert.to_string(UI.QueryWidget(Id(:port), :Value))
          )
          Ops.set(
            @ldapCred,
            "dn",
            Convert.to_string(UI.QueryWidget(Id(:dn), :Value))
          )
          Ops.set(
            @ldapCred,
            "binddn",
            Convert.to_string(UI.QueryWidget(Id(:binddn), :Value))
          )
          Ops.set(
            @ldapCred,
            "password",
            Convert.to_string(UI.QueryWidget(Id(:ldapPassword), :Value))
          )
          cleanLdapCred
          writeSettings(ca)

          cronConfFile = Builtins.sformat(
            "/etc/cron.d/suse.de-yast2-ca-mgm-exportcrl-%1",
            ca
          )

          if !@periodic
            if @file_active
              exportFormat = "PEM"
              exportFormat = "DER" if @fileformat == :ffder
              strret = Convert.to_string(
                YaPI::CaManagement.ExportCRL(
                  {
                    "caName"          => ca,
                    "caPasswd"        => getPassword(ca),
                    "exportFormat"    => exportFormat,
                    "destinationFile" => @crlfile
                  }
                )
              )
              Builtins.y2milestone(
                "ExportCRL(%1) returned %2",
                {
                  "caName"          => ca,
                  "exportFormat"    => exportFormat,
                  "destinationFile" => @crlfile
                },
                ret
              )
              if strret == nil || strret != "1"
                if Popup.YesNoHeadline(
                    _("Export to file failed."),
                    _("Do you want to retry?")
                  )
                  ui = :retry
                end
              else
                Popup.Message(_("Saved to file successfully."))
              end
            end

            if @ldap_active
              boolret = YaPI::CaManagement.ExportCRLToLDAP(
                {
                  "caName"        => ca,
                  "ldapHostname"  => Ops.get(@ldapCred, "hostname", ""),
                  "ldapPort"      => Ops.get(@ldapCred, "port", ""),
                  "destinationDN" => Ops.get(@ldapCred, "dn", ""),
                  "BindDN"        => Ops.get(@ldapCred, "binddn", ""),
                  "ldapPasswd"    => Ops.get(@ldapCred, "ldap_password", "")
                }
              )
              if boolret
                Popup.Message(_("Saved to LDAP successfully."))
              else
                if Popup.YesNoHeadline(
                    _("Export to LDAP failed."),
                    _("Do you want to retry?")
                  )
                  ui = :retry
                end
              end
            end

            # Remove the cronjob if the setting was reset
            SCR.Execute(path(".target.remove"), cronConfFile)
          else
            configString = Builtins.sformat(
              "## Configuration of a cron job to export the CRL of the CA: %1",
              ca
            )
            configString = Ops.add(configString, "\n##")
            configString = Ops.add(
              configString,
              "\n## Created by yast2-ca-management"
            )
            configString = Ops.add(
              configString,
              "\n## Changes to this file will be overwritten by yast2-ca-management"
            )
            configString = Ops.add(
              configString,
              Builtins.sformat(
                "\n## Either use yast or change settings here AND in /var/lib/CAM/%1/exportcrl.conf",
                Builtins.deletechars(ca, " ")
              )
            )
            configString = Ops.add(configString, "\n\n\n")
            hourset = @intervalHours == 24 ?
              Builtins.sformat("%1", @intervalAtHour) :
              Builtins.sformat("*/%1", @intervalHours)
            configString = Ops.add(
              configString,
              Builtins.sformat(
                "* %1 * * *    root    /usr/bin/exportCRL.pl -c /var/lib/CAM/%2/exportcrl.conf",
                hourset,
                Builtins.deletechars(ca, " ")
              )
            )
            if SCR.Write(path(".target.string"), cronConfFile, configString)
              Builtins.y2milestone(
                "Setup cron job for periodic recreation and export of CRLs of CA %1",
                ca
              )
            else
              Builtins.y2error(
                "Failed to set up a cron job for periodic recreation and export of CRLs of CA %1",
                ca
              )
            end
          end
        end
        setSettings
      end until Builtins.contains([:next, :abort], ui)

      UI.CloseDialog

      nil
    end
  end
end

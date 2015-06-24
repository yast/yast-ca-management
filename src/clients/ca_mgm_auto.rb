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
# File:	clients/ca-management_auto.ycp
# Package:	Configuration of ca-management
# Summary:	Client for autoinstallation
# Authors:	Ryan Partridge <rpartridge@novell.com>
#
# $Id$
#
# This is a client for autoinstallation. It takes its arguments,
# goes through the configuration and return the setting.
# Does not do any changes to the configuration.

# @param function to execute
# @param map/list of ca-management settings
# @return [Hash] edited settings, Summary or boolean on success depending on called function
# @example map mm = $[ "FAIL_DELAY" : "77" ];
# @example map ret = WFM::CallFunction ("ca-management_auto", [ "Summary", mm ]);
module Yast
  class CaMgmAutoClient < Client
    def main
      Yast.import "UI"

      textdomain "ca-management"

      Yast.import "Progress"
      Yast.import "Report"
      Yast.import "Users"
      Yast.import "CaMgm"
      Yast.import "Summary"
      Yast.import "Hostname"
      Yast.import "String"

      Yast.include self, "ca-management/new_cert_read_write.rb"
      Yast.include self, "ca-management/util.rb"

      #---------------------------------------------------------------------------
      # MAIN
      #---------------------------------------------------------------------------

      Builtins.y2milestone("----------------------------------------")
      Builtins.y2milestone("ca-management auto started")
      Yast.include self, "ca-management/wizards.rb"

      @ret = nil
      @func = ""
      @param = {}

      # Check arguments
      if Ops.greater_than(Builtins.size(WFM.Args), 0) &&
          Ops.is_string?(WFM.Args(0))
        @func = Convert.to_string(WFM.Args(0))
        if Ops.greater_than(Builtins.size(WFM.Args), 1) &&
            Ops.is_map?(WFM.Args(1))
          @param = Convert.to_map(WFM.Args(1))
        end
      end
      Builtins.y2milestone("func=%1", @func)
      @logparam = deep_copy(@param)
      Ops.set(@logparam, "password", "<non-empty>")
      Builtins.y2milestone("param=%1", @logparam)

      # Create a summary
      if @func == "Summary"
        @ret = Summary()
      # Reset configuration
      elsif @func == "Reset"
        Import({})
        @ret = {}
      # Change configuration (run AutoSequence)
      elsif @func == "Change"
        @ret = caAutoSequence
      # Import configuration
      elsif @func == "Import"
        @ret = Import(@param)
      # Return actual state
      elsif @func == "Export"
        @ret = Export()
      # Return needed packages
      elsif @func == "Packages"
        @ret = AutoPackages()
      # Write given settings
      elsif @func == "Write"
        Yast.import "Progress"
        Progress.off
        @ret = Write()
        Progress.on
      # Read  settings
      elsif @func == "Read"
        Yast.import "Progress"
        Progress.off
        @ret = Read()
        Progress.on
      elsif @func == "GetModified"
        @ret = CaMgm.autoYaSTModified
      elsif @func == "SetModified"
        CaMgm.autoYaSTModified = true
      else
        Builtins.y2error("Unknown function: %1", @func)
        @ret = false
      end

      Builtins.y2milestone("ret=%1", @ret)
      Builtins.y2milestone("ca-management auto finished")
      Builtins.y2milestone("----------------------------------------")

      deep_copy(@ret) 

      # EOF
    end

    # Creates Country items
    # @return a list country items formated for a UI table
    def getAutoCountryList
      result = []
      country_map = Convert.convert(
        Builtins.eval(SCR.Read(path(".target.yast2"), "country.ycp")),
        :from => "any",
        :to   => "map <string, string>"
      )

      country_index = Builtins.mapmap(country_map) { |k, v| { v => k } }

      name_list = Builtins.maplist(country_map) { |k, v| v }

      name_list = Builtins.sort(name_list)

      Builtins.foreach(name_list) do |name|
        result = Builtins.add(
          result,
          Item(
            Id(Ops.get(country_index, name, "")),
            name,
            Ops.get_string(CaMgm.autoYaSTSettings, "country") do
              Timezone.GetCountryForTimezone("")
            end ==
              Ops.get(country_index, name, "")
          )
        )
      end
      deep_copy(result)
    end


    # Autoyast configuration of ca-management
    # For use with autoinstallation.
    # @return sequence result
    def caAutoSequence
      caption = _("CA Configuration")
      confirmPassword = ""
      help_text = _(
        "<p>\n" +
          "YaST generates a default CA and certificate automatically. This CA and certificate\n" +
          "is used for communicating with the Apache server.\n" +
          "Here, change the settings of this CA and certificate or import a CA and certificate from a file.\n" +
          "</p>\n"
      )

      # Initialization dialog contents
      Wizard.CreateDialog

      confirmPassword = Ops.get_string(CaMgm.autoYaSTSettings, "password", "")

      contents = VBox(
        RadioButtonGroup(
          Id(:rb),
          VBox(
            Left(
              RadioButton(
                Id(:import),
                Opt(:notify),
                _("Import Common CA and Certificate"),
                Ops.get_boolean(
                  CaMgm.autoYaSTSettings,
                  "importCertificate",
                  true
                )
              )
            ),
            HBox(
              HSpacing(3),
              VBox(
                HBox(
                  HWeight(
                    2,
                    TextEntry(
                      Id(:pathCert),
                      _("&Path of Certificate"),
                      Ops.get_string(
                        CaMgm.autoYaSTSettings,
                        "pathCertificate",
                        ""
                      )
                    )
                  ),
                  HWeight(
                    1,
                    VBox(
                      Label(""),
                      PushButton(
                        Id(:browseCert),
                        Opt(:notify),
                        Label.BrowseButton
                      )
                    )
                  )
                ),
                HBox(
                  HWeight(
                    1,
                    Password(
                      Id(:pw3),
                      Opt(:hstretch),
                      _("&Password:"),
                      Ops.get_string(CaMgm.autoYaSTSettings, "password", "")
                    )
                  ),
                  HSpacing(2),
                  HWeight(
                    1,
                    Password(
                      Id(:pw4),
                      Opt(:hstretch),
                      _("Co&nfirm Password"),
                      confirmPassword
                    )
                  )
                )
              )
            ),
            Left(
              RadioButton(
                Id(:notImport),
                Opt(:notify),
                _("Generate Common CA and Certificate"),
                !Ops.get_boolean(
                  CaMgm.autoYaSTSettings,
                  "importCertificate",
                  false
                )
              )
            ),
            HBox(
              HSpacing(3),
              VBox(
                HBox(
                  HWeight(
                    1,
                    TextEntry(
                      Id(:id_CAName),
                      _("&CA Name:"),
                      Ops.get_string(
                        CaMgm.autoYaSTSettings,
                        "CAName",
                        "YaST_Default_CA"
                      )
                    )
                  ),
                  HSpacing(2),
                  HWeight(
                    1,
                    TextEntry(
                      Id(:id_commonName),
                      _("&Common Name:"),
                      Ops.get_string(
                        CaMgm.autoYaSTSettings,
                        "ca_commonName",
                        ""
                      )
                    )
                  )
                ),
                HBox(
                  HWeight(
                    1,
                    TextEntry(
                      Id(:email),
                      _("E-Mail"),
                      Ops.get_string(CaMgm.autoYaSTSettings, "server_email", "")
                    )
                  ),
                  HSpacing(2),
                  HWeight(
                    1,
                    ComboBox(
                      Id(:id_country),
                      Opt(:editable),
                      _("C&ountry:"),
                      getAutoCountryList
                    )
                  )
                ),
                HBox(
                  HWeight(
                    1,
                    TextEntry(
                      Id(:id_organisation),
                      _("O&rganization:"),
                      Ops.get_string(CaMgm.autoYaSTSettings, "organisation", "")
                    )
                  ),
                  HSpacing(2),
                  HWeight(
                    1,
                    TextEntry(
                      Id(:id_organisationUnit),
                      _("Or&ganizational Unit:"),
                      Ops.get_string(
                        CaMgm.autoYaSTSettings,
                        "organisationUnit",
                        ""
                      )
                    )
                  )
                ),
                HBox(
                  HWeight(
                    1,
                    TextEntry(
                      Id(:id_locality),
                      _("Loca&lity:"),
                      Ops.get_string(CaMgm.autoYaSTSettings, "locality", "")
                    )
                  ),
                  HSpacing(2),
                  HWeight(
                    1,
                    TextEntry(
                      Id(:id_state),
                      _("&State:"),
                      Ops.get_string(CaMgm.autoYaSTSettings, "state", "")
                    )
                  )
                ),
                HBox(
                  HWeight(
                    1,
                    Password(
                      Id(:pw1),
                      Opt(:hstretch),
                      _("&Password:"),
                      Ops.get_string(CaMgm.autoYaSTSettings, "password", "")
                    )
                  ),
                  HSpacing(2),
                  HWeight(
                    1,
                    Password(
                      Id(:pw2),
                      Opt(:hstretch),
                      _("Co&nfirm Password"),
                      confirmPassword
                    )
                  )
                ),
                Left(
                  CheckBox(
                    Id(:localServerName),
                    Opt(:notify),
                    _("Take Local Server Name"),
                    Ops.get_boolean(
                      CaMgm.autoYaSTSettings,
                      "takeLocalServerName",
                      true
                    )
                  )
                ),
                HBox(
                  HWeight(
                    1,
                    TextEntry(
                      Id(:id_serverName),
                      _("&Server Name:"),
                      Ops.get_string(
                        CaMgm.autoYaSTSettings,
                        "server_commonName",
                        ""
                      )
                    )
                  ),
                  HSpacing(2),
                  HWeight(1, Empty())
                )
              )
            )
          )
        )
      )

      Wizard.SetContents(caption, contents, help_text, false, true)
      Wizard.SetNextButton(:next, Label.FinishButton)

      # Get the user input.
      #
      ret = nil
      begin
        if UI.QueryWidget(Id(:rb), :CurrentButton) == :import
          UI.ChangeWidget(Id(:id_CAName), :Enabled, false)
          UI.ChangeWidget(Id(:id_commonName), :Enabled, false)
          UI.ChangeWidget(Id(:email), :Enabled, false)
          UI.ChangeWidget(Id(:id_country), :Enabled, false)
          UI.ChangeWidget(Id(:id_organisation), :Enabled, false)
          UI.ChangeWidget(Id(:id_organisationUnit), :Enabled, false)
          UI.ChangeWidget(Id(:id_locality), :Enabled, false)
          UI.ChangeWidget(Id(:id_state), :Enabled, false)
          UI.ChangeWidget(Id(:pw1), :Enabled, false)
          UI.ChangeWidget(Id(:pw2), :Enabled, false)
          UI.ChangeWidget(Id(:localServerName), :Enabled, false)
          UI.ChangeWidget(Id(:id_serverName), :Enabled, false)
          UI.ChangeWidget(Id(:pathCert), :Enabled, true)
          UI.ChangeWidget(Id(:browseCert), :Enabled, true)
          UI.ChangeWidget(Id(:pw3), :Enabled, true)
          UI.ChangeWidget(Id(:pw4), :Enabled, true)
        else
          UI.ChangeWidget(Id(:id_CAName), :Enabled, true)
          UI.ChangeWidget(Id(:id_commonName), :Enabled, true)
          UI.ChangeWidget(Id(:email), :Enabled, true)
          UI.ChangeWidget(Id(:id_country), :Enabled, true)
          UI.ChangeWidget(Id(:id_organisation), :Enabled, true)
          UI.ChangeWidget(Id(:id_organisationUnit), :Enabled, true)
          UI.ChangeWidget(Id(:id_locality), :Enabled, true)
          UI.ChangeWidget(Id(:id_state), :Enabled, true)
          UI.ChangeWidget(Id(:localServerName), :Enabled, true)
          UI.ChangeWidget(Id(:pathCert), :Enabled, false)
          UI.ChangeWidget(Id(:browseCert), :Enabled, false)
          UI.ChangeWidget(Id(:pw3), :Enabled, false)
          UI.ChangeWidget(Id(:pw4), :Enabled, false)

          UI.ChangeWidget(Id(:pw1), :Enabled, true)
          UI.ChangeWidget(Id(:pw2), :Enabled, true)

          if Convert.to_boolean(UI.QueryWidget(Id(:localServerName), :Value))
            UI.ChangeWidget(Id(:id_serverName), :Enabled, false)
          else
            UI.ChangeWidget(Id(:id_serverName), :Enabled, true)
          end
        end


        ret = Wizard.UserInput

        if ret == :browseCert
          name = selectFile(false, "*.p12", "Import from ...")
          UI.ChangeWidget(Id(:pathCert), :Value, name) if name != nil
          ret = :again
        end

        if ret == :next || ret == :back
          Builtins.remove(CaMgm.autoYaSTSettings, "certificate")

          notImport = UI.QueryWidget(Id(:rb), :CurrentButton) == :notImport
          if notImport
            confirmPassword = Convert.to_string(
              UI.QueryWidget(Id(:pw2), :Value)
            )
            if Convert.to_string(UI.QueryWidget(Id(:pw1), :Value)) != confirmPassword
              Popup.Error(_("New passwords do not match."))
              ret = :again
            elsif Ops.less_than(Builtins.size(confirmPassword), 4)
              Popup.Error(
                _("Password length should be greater than three characters.")
              )
              ret = :again
            end
          end
          if notImport &&
              Ops.less_or_equal(
                Builtins.size(
                  Convert.to_string(UI.QueryWidget(Id(:id_CAName), :Value))
                ),
                0
              ) &&
              ret != :again
            Popup.Error(_("CA name required."))
            ret = :again
          end
          if notImport &&
              Ops.less_or_equal(
                Builtins.size(
                  Convert.to_string(UI.QueryWidget(Id(:id_commonName), :Value))
                ),
                0
              ) &&
              ret != :again
            Popup.Error(_("Common name required."))
            ret = :again
          end
          if notImport &&
              !check_mail_address(
                Convert.to_string(UI.QueryWidget(Id(:email), :Value))
              ) &&
              ret != :again
            Popup.Error(_("Invalid e-mail format."))
            ret = :again
          end

          if notImport &&
              !Convert.to_boolean(UI.QueryWidget(Id(:localServerName), :Value)) &&
              Ops.less_or_equal(
                Builtins.size(
                  Convert.to_string(UI.QueryWidget(Id(:id_serverName), :Value))
                ),
                0
              ) &&
              ret != :again
            Popup.Error(_("Server name required."))
            ret = :again
          end

          if !notImport && ret != :again
            confirmPassword = Convert.to_string(
              UI.QueryWidget(Id(:pw4), :Value)
            )
            if Convert.to_string(UI.QueryWidget(Id(:pw3), :Value)) != confirmPassword
              Popup.Error(_("New passwords do not match."))
              ret = :again
            elsif Ops.less_than(Builtins.size(confirmPassword), 4)
              Popup.Error(
                _("Password length should be greater than three characters.")
              )
              ret = :again
            end
          end

          retmap = {}

          if !notImport && ret != :again
            command = Builtins.sformat(
              "/usr/bin/openssl base64 -in %1 -e",
              String.Quote(
                Convert.to_string(UI.QueryWidget(Id(:pathCert), :Value))
              )
            )
            retmap = Convert.to_map(
              SCR.Execute(path(".target.bash_output"), command, {})
            )
            Builtins.y2milestone("%1 :%2", command, retmap)
            if Ops.get_integer(retmap, "exit", 0) != 0
              Builtins.y2error("%1 :%2", command, retmap)
              Popup.Error(_("Cannot read the certificate."))
              ret = :again
            end
          end

          if ret != :again
            CaMgm.autoYaSTSettings = {}

            Ops.set(
              CaMgm.autoYaSTSettings,
              "importCertificate",
              Convert.to_symbol(UI.QueryWidget(Id(:rb), :CurrentButton)) == :import
            )
            if Ops.get_boolean(
                CaMgm.autoYaSTSettings,
                "importCertificate",
                false
              )
              Ops.set(
                CaMgm.autoYaSTSettings,
                "certificate",
                strip(Ops.get_string(retmap, "stdout", ""))
              )
              Ops.set(
                CaMgm.autoYaSTSettings,
                "pathCertificate",
                Convert.to_string(UI.QueryWidget(Id(:pathCert), :Value))
              )
              Ops.set(
                CaMgm.autoYaSTSettings,
                "password",
                Convert.to_string(UI.QueryWidget(Id(:pw3), :Value))
              )
            else
              Ops.set(
                CaMgm.autoYaSTSettings,
                "takeLocalServerName",
                Convert.to_boolean(UI.QueryWidget(Id(:localServerName), :Value))
              )
              Ops.set(
                CaMgm.autoYaSTSettings,
                "password",
                Convert.to_string(UI.QueryWidget(Id(:pw1), :Value))
              )
              if !Ops.get_boolean(
                  CaMgm.autoYaSTSettings,
                  "takeLocalServerName",
                  true
                )
                Ops.set(
                  CaMgm.autoYaSTSettings,
                  "server_commonName",
                  Convert.to_string(UI.QueryWidget(Id(:id_serverName), :Value))
                )
              end
              Ops.set(
                CaMgm.autoYaSTSettings,
                "CAName",
                Convert.to_string(UI.QueryWidget(Id(:id_CAName), :Value))
              )
              Ops.set(
                CaMgm.autoYaSTSettings,
                "ca_commonName",
                Convert.to_string(UI.QueryWidget(Id(:id_commonName), :Value))
              )
              Ops.set(
                CaMgm.autoYaSTSettings,
                "server_email",
                Convert.to_string(UI.QueryWidget(Id(:email), :Value))
              )
              Ops.set(
                CaMgm.autoYaSTSettings,
                "country",
                Convert.to_string(UI.QueryWidget(Id(:id_country), :Value))
              )
              Ops.set(
                CaMgm.autoYaSTSettings,
                "organisation",
                Convert.to_string(UI.QueryWidget(Id(:id_organisation), :Value))
              )
              Ops.set(
                CaMgm.autoYaSTSettings,
                "organisationUnit",
                Convert.to_string(
                  UI.QueryWidget(Id(:id_organisationUnit), :Value)
                )
              )
              Ops.set(
                CaMgm.autoYaSTSettings,
                "locality",
                Convert.to_string(UI.QueryWidget(Id(:id_locality), :Value))
              )
              Ops.set(
                CaMgm.autoYaSTSettings,
                "state",
                Convert.to_string(UI.QueryWidget(Id(:id_state), :Value))
              )
            end
          end
        end
      end until ret == :next || ret == :abort || ret == :back

      UI.CloseDialog
      deep_copy(ret)
    end

    # Get all ca-management settings from the first parameter
    # (For use by autoinstallation.)
    # @param [Hash] settings The YCP structure to be imported.
    # @return [Boolean] True on success
    def Import(settings)
      settings = deep_copy(settings)
      ret = true

      CaMgm.autoYaSTSettings = {}


      Ops.set(
        CaMgm.autoYaSTSettings,
        "importCertificate",
        Ops.get_boolean(settings, "importCertificate", false)
      )
      if Ops.get_boolean(CaMgm.autoYaSTSettings, "importCertificate", false)
        # importing CA/certificate
        Ops.set(
          CaMgm.autoYaSTSettings,
          "certificate",
          Ops.get_string(settings, "certificate", "")
        )
        Ops.set(
          CaMgm.autoYaSTSettings,
          "pathCertificate",
          Ops.get_string(settings, "pathCertificate", "")
        )
        Ops.set(
          CaMgm.autoYaSTSettings,
          "password",
          Ops.get_string(settings, "password", "")
        )
      else
        #create one
        if Builtins.haskey(settings, "password")
          Ops.set(
            CaMgm.autoYaSTSettings,
            "password",
            Ops.get_string(settings, "password", "")
          )
        end

        Ops.set(
          CaMgm.autoYaSTSettings,
          "takeLocalServerName",
          Ops.get_boolean(settings, "takeLocalServerName", true)
        )
        if Ops.get_boolean(settings, "takeLocalServerName", true)
          host_ips = getHostIPs
          hostname_bak = ""

          Builtins.foreach(host_ips) do |key, value|
            hostname_bak = key if value == "DNS"
          end

          retmap = Convert.to_map(
            SCR.Execute(path(".target.bash_output"), "/bin/hostname --long", {})
          )
          Builtins.y2milestone("Hostname :%1", retmap)
          if Ops.get_integer(retmap, "exit", 1) != 0
            if hostname_bak == ""
              Ops.set(retmap, "stdout", Hostname.CurrentFQ)
            else
              Ops.set(retmap, "stdout", hostname_bak)
            end
          end
          Ops.set(
            CaMgm.autoYaSTSettings,
            "server_commonName",
            strip(Ops.get_string(retmap, "stdout", "linux.#{Hostname.DefaultDomain}"))
          )
        else
          if Builtins.haskey(settings, "server_commonName")
            Ops.set(
              CaMgm.autoYaSTSettings,
              "server_commonName",
              Ops.get_string(settings, "server_commonName", "")
            )
          end
        end
        if Builtins.haskey(settings, "CAName")
          Ops.set(
            CaMgm.autoYaSTSettings,
            "CAName",
            Ops.get_string(settings, "CAName", "YaST_Default_CA")
          )
        end
        if Builtins.haskey(settings, "ca_commonName")
          Ops.set(
            CaMgm.autoYaSTSettings,
            "ca_commonName",
            Ops.get_string(settings, "ca_commonName", "")
          )
        end
        if Builtins.haskey(settings, "server_email")
          Ops.set(
            CaMgm.autoYaSTSettings,
            "server_email",
            Ops.get_string(settings, "server_email", "")
          )
        end
        if Builtins.haskey(settings, "country")
          Ops.set(
            CaMgm.autoYaSTSettings,
            "country",
            Ops.get_string(settings, "country", "")
          )
        end
        if Builtins.haskey(settings, "organisation")
          Ops.set(
            CaMgm.autoYaSTSettings,
            "organisation",
            Ops.get_string(settings, "organisation", "")
          )
        end
        if Builtins.haskey(settings, "organisationUnit")
          Ops.set(
            CaMgm.autoYaSTSettings,
            "organisationUnit",
            Ops.get_string(settings, "organisationUnit", "")
          )
        end
        if Builtins.haskey(settings, "locality")
          Ops.set(
            CaMgm.autoYaSTSettings,
            "locality",
            Ops.get_string(settings, "locality", "")
          )
        end
        if Builtins.haskey(settings, "state")
          Ops.set(
            CaMgm.autoYaSTSettings,
            "state",
            Ops.get_string(settings, "state", "")
          )
        end
      end

      ret
    end

    # Dump the ca-management settings to a single map
    # (For use by autoinstallation.)
    # @return [Hash] Dumped settings (later acceptable by Import ())
    def Export
      deep_copy(CaMgm.autoYaSTSettings)
    end

    # Return packages needed to be installed and removed during
    # Autoinstallation to insure module has all needed software
    # installed.
    # @return [Hash] with 2 lists.
    def AutoPackages
      { "install" => ["openssl"], "remove" => [] }
    end

    # Create a textual summary and a list of unconfigured cards
    # @return summary of the current configuration
    def Summary
      # Configuration summary text for autoyast
      summary = ""

      if Ops.get_boolean(CaMgm.autoYaSTSettings, "importCertificate", false)
        summary = Summary.AddHeader(summary, _("Import Certificate from File"))
        summary = Summary.AddLine(
          summary,
          Ops.get_string(CaMgm.autoYaSTSettings, "pathCertificate", "")
        )
      else
        summary = Summary.AddHeader(summary, _("Server Name"))
        if Ops.get_boolean(CaMgm.autoYaSTSettings, "takeLocalServerName", true)
          summary = Summary.AddLine(summary, _("[local server name]"))
        else
          summary = Summary.AddLine(
            summary,
            Ops.get_string(CaMgm.autoYaSTSettings, "server_commonName", "")
          )
        end
        summary = Summary.AddHeader(summary, _("CA Name"))
        summary = Summary.AddLine(
          summary,
          Ops.get_string(CaMgm.autoYaSTSettings, "CAName", "YaST_Default_CA")
        )
        summary = Summary.AddHeader(summary, _("Common Name"))
        summary = Summary.AddLine(
          summary,
          Ops.get_locale(
            CaMgm.autoYaSTSettings,
            "ca_commonName",
            _("[not set]")
          )
        )
        summary = Summary.AddHeader(summary, _("Email"))
        summary = Summary.AddLine(
          summary,
          Ops.get_locale(CaMgm.autoYaSTSettings, "server_email", _("[not set]"))
        )
        summary = Summary.AddHeader(summary, _("Country"))
        summary = Summary.AddLine(
          summary,
          Ops.get_locale(CaMgm.autoYaSTSettings, "country", _("[not set]"))
        )
        summary = Summary.AddHeader(summary, _("Organization"))
        summary = Summary.AddLine(
          summary,
          Ops.get_locale(CaMgm.autoYaSTSettings, "organisation", _("[not set]"))
        )
        summary = Summary.AddHeader(summary, _("Organizational Unit"))
        summary = Summary.AddLine(
          summary,
          Ops.get_locale(
            CaMgm.autoYaSTSettings,
            "organisationUnit",
            _("[not set]")
          )
        )
        summary = Summary.AddHeader(summary, _("Locality"))
        summary = Summary.AddLine(
          summary,
          Ops.get_locale(CaMgm.autoYaSTSettings, "locality", _("[not set]"))
        )
        summary = Summary.AddHeader(summary, _("State"))
        summary = Summary.AddLine(
          summary,
          Ops.get_locale(CaMgm.autoYaSTSettings, "state", _("[not set]"))
        )

        summary = Summary.AddHeader(summary, _("Password"))
        if Ops.less_or_equal(
            Builtins.size(
              Ops.get_string(CaMgm.autoYaSTSettings, "password", "")
            ),
            0
          )
          summary = Summary.AddLine(summary, _("[not set]"))
        else
          summary = Summary.AddLine(summary, _("[set]"))
        end
      end

      summary
    end


    # Write all ca-management settings
    # @return true on success
    def Write
      success = true
      caption = _("Generating Common Server Certificate")
      steps = 2
      sl = 500

      Report.DisplayErrors(true, 5)
      Report.DisplayMessages(true, 5)

      # We do not set help text here, because it was set outside
      Progress.New(
        caption,
        " ",
        steps,
        [
          # Progress stage 1/2
          _("Read server information"),
          # Progress stage 2/2
          _("Create the default CA and server certificate")
        ],
        [
          # Progress stage 1/2
          _("Read server information"),
          # Progress step 2/2
          _("Creating the default CA and server certificate..."),
          # Progress finished
          _("Finished")
        ],
        ""
      )

      # Read server information

      tmpfile = Ops.add(
        Convert.to_string(SCR.Read(path(".target.tmpdir"))),
        "/YaST-Servercert.p12"
      )

      Progress.NextStage
      if Ops.get_boolean(CaMgm.autoYaSTSettings, "importCertificate", false)
        # importing CA/certificate
        command = Builtins.sformat(
          "/usr/bin/openssl base64 -out %1 -d",
          String.Quote(tmpfile)
        )
        SCR.Execute(
          path(".target.bash_input"),
          command,
          Ops.get_string(CaMgm.autoYaSTSettings, "certificate", "")
        )
      else
        # create one
        if Ops.get_boolean(CaMgm.autoYaSTSettings, "takeLocalServerName", true)
          host_ips = getHostIPs
          hostname_bak = ""

          Builtins.foreach(host_ips) do |key, value|
            hostname_bak = key if value == "DNS"
          end

          retmap = Convert.to_map(
            SCR.Execute(path(".target.bash_output"), "/bin/hostname --long", {})
          )

          Builtins.y2milestone("Hostname :%1", retmap)
          if Ops.get_integer(retmap, "exit", 1) != 0
            if hostname_bak == ""
              Ops.set(retmap, "stdout", Hostname.CurrentFQ)
            else
              Ops.set(retmap, "stdout", hostname_bak)
            end
          end
          CaMgm.prop_server_commonName = strip(
            Ops.get_string(retmap, "stdout", "linux.#{Hostname.DefaultDomain}")
          )
        else
          CaMgm.prop_server_commonName = Ops.get_string(
            CaMgm.autoYaSTSettings,
            "server_commonName",
            ""
          )
        end

        CaMgm.prop_selection = :def
        CaMgm.prop_ca_commonName = Ops.get_string(
          CaMgm.autoYaSTSettings,
          "ca_commonName",
          ""
        )
        CaMgm.prop_CAName = Ops.get_string(
          CaMgm.autoYaSTSettings,
          "CAName",
          "YaST_Default_CA"
        )
        CaMgm.prop_country = Ops.get_string(
          CaMgm.autoYaSTSettings,
          "country",
          ""
        )
        CaMgm.prop_email = Ops.get_string(
          CaMgm.autoYaSTSettings,
          "server_email",
          ""
        )
        CaMgm.prop_organisation = Ops.get_string(
          CaMgm.autoYaSTSettings,
          "organisation",
          ""
        )
        CaMgm.prop_organisationUnit = Ops.get_string(
          CaMgm.autoYaSTSettings,
          "organisationUnit",
          ""
        )
        CaMgm.prop_locality = Ops.get_string(
          CaMgm.autoYaSTSettings,
          "locality",
          ""
        )
        CaMgm.prop_state = Ops.get_string(CaMgm.autoYaSTSettings, "state", "")
        CaMgm.prop_password = Ops.get_string(
          CaMgm.autoYaSTSettings,
          "password",
          ""
        )
      end

      Progress.NextStage

      # write settings

      if success
        if Ops.get_boolean(CaMgm.autoYaSTSettings, "importCertificate", false)
          importret = YaPI::CaManagement.ImportCommonServerCertificate(
            {
              "passwd" => Ops.get_string(CaMgm.autoYaSTSettings, "password", ""),
              "inFile" => tmpfile
            }
          )
          Builtins.y2milestone(
            "ImportCommonServerCertificate() return %1",
            importret
          )
          success = false if importret == nil || !importret
        else
          success = create_default_CA_certificate
        end
      end
      if !success
        # Error message
        Report.Error(_("Cannot create certificates."))
      end

      Builtins.sleep(sl)

      # Progress finished
      Progress.NextStage
      Builtins.sleep(sl)

      success
    end

    # Read ca-management defaults
    # @return true on success
    def Read
      servercert = nil
      servercert = Convert.to_map(
        YaPI::CaManagement.ReadFile(
          {
            "inFile"   => "/etc/ssl/servercerts/servercert.pem",
            "type"     => "parsed",
            "datatype" => "CERTIFICATE",
            "inForm"   => "PEM"
          }
        )
      )

      found = servercert != nil ? true : false

      hostname = "linux"
      domain = Hostname.DefaultDomain
      retmap = Convert.to_map(
        SCR.Execute(path(".target.bash_output"), "/bin/hostname -s", {})
      )

      if Ops.get_integer(retmap, "exit", 1) == 0
        hostname = strip(Ops.get_string(retmap, "stdout", "linux"))
      end

      retmap = Convert.to_map(
        SCR.Execute(path(".target.bash_output"), "/bin/hostname --domain", {})
      )

      if Ops.get_integer(retmap, "exit", 1) == 0
        domain = strip(Ops.get_string(retmap, "stdout", Hostname.DefaultDomain))
      end

      if found
        serverCertDN = Ops.get_map(servercert, "DN_HASH", {})
        serverCertIssuer = Ops.get_map(servercert, "ISSUER_HASH", {})


        Ops.set(CaMgm.autoYaSTSettings, "takeLocalServerName", false)
        Ops.set(CaMgm.autoYaSTSettings, "password", "ENTER PASSWORD HERE")
        Ops.set(
          CaMgm.autoYaSTSettings,
          "server_commonName",
          Ops.get_string(
            Ops.get_list(serverCertDN, "CN", []),
            0,
            Ops.add(Ops.add(hostname, "."), domain)
          )
        )
        Ops.set(CaMgm.autoYaSTSettings, "CAName", "YaST_Default_CA")
        Ops.set(
          CaMgm.autoYaSTSettings,
          "ca_commonName",
          Ops.get_string(
            Ops.get_list(serverCertIssuer, "CN", []),
            0,
            Ops.add(Ops.add("YaST Default CA " + "(", domain), ")")
          )
        )
        Ops.set(
          CaMgm.autoYaSTSettings,
          "server_email",
          Ops.get_string(
            Ops.get_list(serverCertDN, "emailAddress", []),
            0,
            Ops.add("postmaster@", domain)
          )
        )
        Ops.set(
          CaMgm.autoYaSTSettings,
          "country",
          Ops.get_string(Ops.get_list(serverCertDN, "C", []), 0, "US")
        )
        Ops.set(
          CaMgm.autoYaSTSettings,
          "organisation",
          Ops.get_string(Ops.get_list(serverCertDN, "O", []), 0, "")
        )
        Ops.set(
          CaMgm.autoYaSTSettings,
          "organisationUnit",
          Ops.get_string(Ops.get_list(serverCertDN, "OU", []), 0, "")
        )
        Ops.set(
          CaMgm.autoYaSTSettings,
          "locality",
          Ops.get_string(Ops.get_list(serverCertDN, "L", []), 0, "")
        )
        Ops.set(
          CaMgm.autoYaSTSettings,
          "state",
          Ops.get_string(Ops.get_list(serverCertDN, "ST", []), 0, "")
        )
      else
        Ops.set(CaMgm.autoYaSTSettings, "takeLocalServerName", true)
        Ops.set(CaMgm.autoYaSTSettings, "password", "ENTER PASSWORD HERE")
        Ops.set(CaMgm.autoYaSTSettings, "CAName", "YaST_Default_CA")
        Ops.set(
          CaMgm.autoYaSTSettings,
          "ca_commonName",
          Ops.add(Ops.add("YaST Default CA " + "(", domain), ")")
        )
        Ops.set(
          CaMgm.autoYaSTSettings,
          "server_email",
          Ops.add("postmaster@", domain)
        )
        Ops.set(
          CaMgm.autoYaSTSettings,
          "country",
          Timezone.GetCountryForTimezone("")
        )
        Ops.set(CaMgm.autoYaSTSettings, "organisation", "")
        Ops.set(CaMgm.autoYaSTSettings, "organisationUnit", "")
        Ops.set(CaMgm.autoYaSTSettings, "locality", "")
        Ops.set(CaMgm.autoYaSTSettings, "state", "")
      end
      true
    end
  end
end

Yast::CaMgmAutoClient.new.main

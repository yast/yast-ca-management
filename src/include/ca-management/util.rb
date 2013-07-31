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
# File:        include/ca-management/util.ycp
# Package:     Configuration of CAs
# Summary:     Util definitions
# Authors:     Stefan Schubert (schubi@suse.de)
#
# $Id$
module Yast
  module CaManagementUtilInclude
    def initialize_ca_management_util(include_target)
      Yast.import "UI"

      textdomain "ca-management"

      Yast.import "CaMgm"
      Yast.import "Label"
      Yast.import "Popup"
      Yast.import "Wizard"
      Yast.import "Hostname"
      Yast.import "YaPI::CaManagement"

      Yast.include include_target, "ca-management/popup.rb"
    end

    # returns true if char is blank (newline, tab or space)
    # @param [String] s single char string
    # @return [Boolean] blank/non blank
    def isBlank(s)
      return true if s == "\n" || s == "\t" || s == " "
      false
    end

    # removes trailing and leading blank chars from string.
    #   eg: "  as df  " -> "as df"
    # @param [String] str string source string
    # @return [String] stripped string
    def strip(str)
      #emtpy  string
      return "" if Builtins.size(str) == 0

      bound = Builtins.size(str)
      first = 0
      last = Ops.subtract(Builtins.size(str), 1)
      # find first non-blank char
      while Ops.less_than(first, bound) &&
          isBlank(Builtins.substring(str, first, 1))
        first = Ops.add(first, 1)
      end

      while Ops.greater_or_equal(last, 0) &&
          isBlank(Builtins.substring(str, last, 1))
        last = Ops.subtract(last, 1)
      end
      if Ops.greater_or_equal(last, first)
        return Builtins.substring(
          str,
          first,
          Ops.add(Ops.subtract(last, first), 1)
        )
      end
      ""
    end




    # Asking for a existing or new file
    # @param flag new file, filter, headline
    # @return the pathname or a empty string if aborted
    def selectFile(newFile, filterString, headline)
      display = UI.GetDisplayInfo
      ret = ""

      if Ops.greater_than(
          SCR.Read(path(".target.size"), "/opt/kde3/bin/kfiledialog"),
          0
        ) &&
          strip(Builtins.getenv("KDE_FULL_SESSION")) == "true" &&
          !Ops.get_boolean(display, "TextMode", false)
        # using kfiledialog
        retmap = Convert.to_map(
          SCR.Execute(
            path(".target.bash_output"),
            Builtins.sformat(
              "/opt/kde3/bin/kfiledialog \"\" \"%1\"",
              filterString
            ),
            {}
          )
        )
        Builtins.y2milestone("kfiledialog :%1", retmap)
        ret = strip(Ops.get_string(retmap, "stdout", ""))
      else
        if newFile
          ret = UI.AskForSaveFileName(".", filterString, headline)
        else
          ret = UI.AskForExistingFile(".", filterString, headline)
        end
      end

      ret
    end


    # Creates Country items
    # @return a list country items formated for a UI table
    def getCountryList
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
            CaMgm.country == Ops.get(country_index, name, "")
          )
        )
      end
      deep_copy(result)
    end


    # See RFC 2822, 3.4
    # But for now, no-spaces@valid_domainname
    # @param [String] address an address to check
    # @return valid?check_mail_address
    def check_mail_address(address)
      parts = Builtins.splitstring(address, "@")
      return false if Builtins.size(parts) != 2
      address = Ops.get(parts, 0, "")

      address != "" && Builtins.findfirstof(address, " ") == nil &&
        Hostname.CheckDomain(Ops.get(parts, 1, ""))
    end

    # Change password Dialog
    #
    def changePassword(_CAname, certificate)
      title = _("Change Certificate Password")
      title = _("Change CA Password") if certificate == ""

      # asking user
      UI.OpenDialog(
        Opt(:decorated),
        HBox(
          HSpacing(2),
          VBox(
            VSpacing(1),
            # popup window header
            Heading(title),
            VSpacing(1),
            Password(Id(:oldpw), Opt(:hstretch), _("&Old Password:")),
            VSpacing(1),
            Password(Id(:newpw), Opt(:hstretch), _("&New Password:")),
            Password(Id(:verifynewpw), Opt(:hstretch), _("&Verify Password:")),
            HBox(
              PushButton(Id(:ok), Opt(:default, :key_F10), Label.OKButton),
              HStretch(),
              PushButton(Id(:cancel), Opt(:key_F9), Label.AbortButton)
            ), # push button label
            VSpacing(1)
          ),
          HSpacing(2)
        )
      )

      UI.SetFocus(Id(:oldpw))
      ui = nil
      begin
        ui = Convert.to_symbol(UI.UserInput)

        if ui == :ok
          oldPassword = Convert.to_string(UI.QueryWidget(Id(:oldpw), :Value))
          newPassword = Convert.to_string(UI.QueryWidget(Id(:newpw), :Value))
          verifyPassword = Convert.to_string(
            UI.QueryWidget(Id(:verifynewpw), :Value)
          )

          # checking password

          if newPassword != verifyPassword
            Popup.Error(_("New passwords do not match."))
            ui = :again
          elsif Ops.less_than(Builtins.size(newPassword), 4)
            Popup.Error(
              _(
                "The new password is too short to use it for the certificates.\nEnter a valid password for the certificates.\n"
              )
            )
            ui = :again
          else
            Builtins.y2milestone(
              "Change password for '%1' '%2'",
              _CAname,
              certificate
            )
            data = {
              "caName"      => _CAname,
              "certificate" => certificate,
              "oldPasswd"   => oldPassword,
              "newPasswd"   => newPassword
            }
            ret = YaPI::CaManagement.ChangePassword(data)

            if ret == nil
              showErrorCaManagement
              ui = :again
            else
              if certificate == ""
                Ops.set(CaMgm.passwdMap, _CAname, newPassword)
                Popup.Message(_("CA Password changed."))
              else
                Popup.Message(_("Certificate Password changed."))
              end
            end
          end
        end
      end until Builtins.contains([:ok, :cancel], ui)
      UI.CloseDialog

      nil
    end


    # Dialog for asking a CA password. Returns the password
    #   without asking if is has already input before.
    # @param [String] CAname
    # @return [String] password
    def getPassword(_CAname)
      password = nil

      if !Builtins.haskey(CaMgm.passwdMap, _CAname)
        # asking user
        UI.OpenDialog(
          Opt(:decorated),
          HBox(
            HSpacing(2),
            VBox(
              VSpacing(1),
              # popup window header
              Heading(_("Enter CA Password")),
              VSpacing(1),
              Password(Id(:entry), Opt(:hstretch), _("&Password:")),
              VSpacing(1),
              HBox(
                PushButton(Id(:ok), Opt(:default, :key_F10), Label.OKButton),
                HStretch(),
                PushButton(Id(:cancel), Opt(:key_F9), Label.AbortButton)
              ), # push button label
              VSpacing(1)
            ),
            HSpacing(2)
          )
        )

        UI.SetFocus(Id(:entry))
        ui = nil
        begin
          ui = Convert.to_symbol(UI.UserInput)
          password = Convert.to_string(UI.QueryWidget(Id(:entry), :Value))
          if ui == :cancel
            password = nil
          else
            # checking password
            ret = nil
            ret = YaPI::CaManagement.UpdateDB(
              { "caName" => _CAname, "caPasswd" => password }
            )
            if ret == nil || ret == false
              showErrorCaManagement
              password = nil
              ui = :retry
            else
              # saving for next call
              Builtins.y2milestone("Checking password for %1 OK", _CAname)
              Ops.set(CaMgm.passwdMap, _CAname, password)
            end
          end
        end until Builtins.contains([:ok, :cancel], ui)
        UI.CloseDialog
      else
        # already available
        password = Ops.get_string(CaMgm.passwdMap, _CAname, "")
      end

      password
    end

    # Dialog for exporting CA/Certificate/CRL to LDAP
    #
    # @param "CA" "CRL" "CERT" "subjectAltName"
    # @return true ( success )
    def exportToLDAP(kind, _CAname, commonName, email, certificate, subjectAltName)
      kindmap = { "CA" => "ca", "CRL" => "crl", "CERT" => "certificate" }
      password = ""
      hostname = ""
      port = ""
      dn = []
      binddn = ""
      defaultv = nil
      passwordTerm = VBox()

      Builtins.y2milestone(
        "exportToLDAP type: %1; CAname: %2, commonName: %3, email: %4, certificate: %5, subjectAltName: %6",
        kind,
        _CAname,
        commonName,
        email,
        certificate,
        subjectAltName
      )

      passwordTerm = Builtins.add(
        passwordTerm,
        Password(Id(:password), Opt(:hstretch), _("LDAP P&assword:"))
      )

      if kind == "CERT"
        if Ops.greater_than(Builtins.size(subjectAltName), 0)
          defaultv = YaPI::CaManagement.ReadLDAPExportDefaults(
            {
              "type"           => Ops.get_string(kindmap, kind, ""),
              "caName"         => _CAname,
              "commonName"     => commonName,
              "emailAddress"   => email,
              "subjectAltName" => subjectAltName
            }
          )
        else
          defaultv = YaPI::CaManagement.ReadLDAPExportDefaults(
            {
              "type"         => Ops.get_string(kindmap, kind, ""),
              "caName"       => _CAname,
              "commonName"   => commonName,
              "emailAddress" => email
            }
          )
        end
        passwordTerm = Builtins.add(
          passwordTerm,
          Password(Id(:keyPasswd), Opt(:hstretch), _("Certificate &Password:"))
        )
        passwordTerm = Builtins.add(
          passwordTerm,
          HBox(
            Password(Id(:p12Passwd), Opt(:hstretch), _("&New Password:")),
            Password(Id(:verifyPassword), Opt(:hstretch), _("&Verify Password"))
          )
        )
      else
        defaultv = YaPI::CaManagement.ReadLDAPExportDefaults(
          { "type" => Ops.get_string(kindmap, kind, ""), "caName" => _CAname }
        )
      end

      if defaultv == nil
        # Error: Checking if there is have already a config has been established
        messageMap = YaPI.Error
        if kind == "CERT"
          Builtins.y2milestone(
            "ReadLDAPExportDefaults(%1) returns %2",
            {
              "type"           => Ops.get_string(kindmap, kind, ""),
              "caName"         => _CAname,
              "commonName"     => commonName,
              "emailAddress"   => email,
              "subjectAltName" => subjectAltName
            },
            messageMap
          )
        else
          Builtins.y2milestone(
            "ReadLDAPExportDefaults(%1) returns %2",
            { "type" => Ops.get_string(kindmap, kind, ""), "caName" => _CAname },
            messageMap
          )
        end

        if Ops.get_string(messageMap, "code", "") == "LDAP_CONFIG_NEEDED"
          UI.OpenDialog(
            Opt(:decorated),
            HBox(
              HSpacing(2),
              VBox(
                VSpacing(1),
                # popup window header
                Heading(_("LDAP Initialization")),
                Label(
                  _(
                    "LDAP must initialize for the CA management.\nEnter the required LDAP password.\n"
                  )
                ),
                VSpacing(1),
                Password(Id(:password), Opt(:hstretch), _("P&assword:")),
                VSpacing(1),
                HBox(
                  PushButton(Id(:ok), Opt(:default, :key_F10), Label.OKButton),
                  HStretch(),
                  PushButton(Id(:cancel), Opt(:key_F9), Label.AbortButton)
                ), # push button label
                VSpacing(1)
              ),
              HSpacing(2)
            )
          )

          UI.SetFocus(Id(:password))
          ui2 = nil
          begin
            ui2 = Convert.to_symbol(UI.UserInput)
            password = Convert.to_string(UI.QueryWidget(Id(:password), :Value))
            if ui2 == :ok
              if YaPI::CaManagement.InitLDAPcaManagement(
                  { "ldapPasswd" => password }
                )
                if kind == "CERT"
                  defaultv = YaPI::CaManagement.ReadLDAPExportDefaults(
                    {
                      "type"         => Ops.get_string(kindmap, kind, ""),
                      "caName"       => _CAname,
                      "commonName"   => commonName,
                      "emailAddress" => email
                    }
                  )
                else
                  defaultv = YaPI::CaManagement.ReadLDAPExportDefaults(
                    {
                      "type"   => Ops.get_string(kindmap, kind, ""),
                      "caName" => _CAname
                    }
                  )
                end
              else
                showErrorCaManagement
              end
            end
          end until Builtins.contains([:ok, :cancel], ui2)
          UI.CloseDialog
        end
      end

      if defaultv == nil
        showErrorCaManagement
      else
        hostname = Ops.get_string(defaultv, "ldapHostname", "")
        port = Ops.get_string(defaultv, "ldapPort", "")
        dn = Ops.get_list(defaultv, "destinationDN", [])
        binddn = Ops.get_string(defaultv, "BindDN", "")
      end

      Builtins.y2milestone("ReadLDAPExportDefaults() returned %1", defaultv)

      UI.OpenDialog(
        Opt(:decorated),
        HBox(
          HSpacing(2),
          VBox(
            VSpacing(1),
            # popup window header
            Heading(_("Export to LDAP")),
            VSpacing(1),
            TextEntry(Id(:hostname), _("&Host Name:"), hostname),
            TextEntry(Id(:port), _("&Port:"), port),
            HBox(HWeight(1, ComboBox(Id(:dn), Opt(:editable), _("&DN:"), dn))),
            TextEntry(Id(:binddn), _("&Bind DN:"), binddn),
            passwordTerm,
            VSpacing(1),
            HBox(
              PushButton(Id(:ok), Opt(:default, :key_F10), Label.OKButton),
              HStretch(),
              PushButton(Id(:cancel), Opt(:key_F9), Label.AbortButton)
            ), # push button label
            VSpacing(1)
          ),
          HSpacing(2)
        )
      )

      UI.SetFocus(Id(:hostname))
      ui = nil
      begin
        ui = Convert.to_symbol(UI.UserInput)

        password = Convert.to_string(UI.QueryWidget(Id(:password), :Value))
        hostname = Convert.to_string(UI.QueryWidget(Id(:hostname), :Value))
        port = Convert.to_string(UI.QueryWidget(Id(:port), :Value))
        stringDN = Convert.to_string(UI.QueryWidget(Id(:dn), :Value))
        binddn = Convert.to_string(UI.QueryWidget(Id(:binddn), :Value))

        if ui == :cancel
          password = nil
        else
          # export to LDAP
          ret = nil
          if kind == "CA"
            ret = YaPI::CaManagement.ExportCAToLDAP(
              {
                "caName"        => _CAname,
                "ldapHostname"  => hostname,
                "ldapPort"      => port,
                "destinationDN" => stringDN,
                "BindDN"        => binddn,
                "ldapPasswd"    => password
              }
            )
          end
          if kind == "CRL"
            ret = YaPI::CaManagement.ExportCRLToLDAP(
              {
                "caName"        => _CAname,
                "ldapHostname"  => hostname,
                "ldapPort"      => port,
                "destinationDN" => stringDN,
                "BindDN"        => binddn,
                "ldapPasswd"    => password
              }
            )
          end
          if kind == "CERT"
            keyPasswd = Convert.to_string(
              UI.QueryWidget(Id(:keyPasswd), :Value)
            )
            p12Passwd = Convert.to_string(
              UI.QueryWidget(Id(:p12Passwd), :Value)
            )

            if Ops.greater_than(Builtins.size(keyPasswd), 0)
              # p12Passwd is required is keyPasswd has been given
              if UI.QueryWidget(Id(:p12Passwd), :Value) !=
                  UI.QueryWidget(Id(:verifyPassword), :Value)
                Popup.Error(_("New passwords do not match."))
                ui = :again
              else
                ret = YaPI::CaManagement.ExportCertificateToLDAP(
                  {
                    "caName"        => _CAname,
                    "caPasswd"      => getPassword(_CAname),
                    "certificate"   => certificate,
                    "ldapHostname"  => hostname,
                    "ldapPort"      => port,
                    "destinationDN" => stringDN,
                    "BindDN"        => binddn,
                    "ldapPasswd"    => password,
                    "keyPasswd"     => keyPasswd,
                    "p12Passwd"     => p12Passwd
                  }
                )
              end
            else
              ret = YaPI::CaManagement.ExportCertificateToLDAP(
                {
                  "caName"        => _CAname,
                  "certificate"   => certificate,
                  "ldapHostname"  => hostname,
                  "ldapPort"      => port,
                  "destinationDN" => stringDN,
                  "BindDN"        => binddn,
                  "ldapPasswd"    => password
                }
              )
            end
          end
          if ui == :ok
            # Checking error
            if ret == nil || ret == false
              showErrorCaManagement
              ret = false
            else
              Popup.Message(_("Saved to LDAP successfully."))
            end
          end
        end
      end until Builtins.contains([:ok, :cancel], ui)
      UI.CloseDialog

      nil
    end


    # Dialog for exporting CA to file
    # @param [String] CAname
    # @return true ( success )
    def exportCAtoFile(_CAname)
      UI.OpenDialog(
        Opt(:decorated),
        HBox(
          HSpacing(2),
          VBox(
            VSpacing(1),
            # popup window header
            Heading(_("Export CA to File")),
            VSpacing(1),
            Frame(
              _("Export Format"),
              RadioButtonGroup(
                Id(:rb),
                VBox(
                  Left(
                    RadioButton(
                      Id(:PEM_CERT),
                      Opt(:notify),
                      _("O&nly the Certificate in PEM Format"),
                      true
                    )
                  ),
                  Left(
                    RadioButton(
                      Id(:PEM_KEY),
                      Opt(:notify),
                      _("Only the Key &Unencrypted in PEM Format")
                    )
                  ),
                  Left(
                    RadioButton(
                      Id(:PEM_ENCKEY),
                      Opt(:notify),
                      _("Only the &Key Encrypted in PEM Format")
                    )
                  ),
                  Left(
                    RadioButton(
                      Id(:PEM_CERT_KEY),
                      Opt(:notify),
                      _("Ce&rtificate and the Key Unencrypted in PEM Format")
                    )
                  ),
                  Left(
                    RadioButton(
                      Id(:PEM_CERT_ENCKEY),
                      Opt(:notify),
                      _("C&ertificate and the Key Encrypted in PEM Format")
                    )
                  ),
                  Left(
                    RadioButton(
                      Id(:DER_CERT),
                      Opt(:notify),
                      _("&Certificate in DER Format")
                    )
                  ),
                  Left(
                    RadioButton(
                      Id(:PKCS12),
                      Opt(:notify),
                      _("Cer&tificate and the Key in PKCS12 Format")
                    )
                  ),
                  Left(
                    RadioButton(
                      Id(:PKCS12_CHAIN),
                      Opt(:notify),
                      _("&Like PKCS12 and Include the CA Chain")
                    )
                  )
                )
              )
            ),
            HBox(
              Password(Id(:PK12password), Opt(:hstretch), _("&New Password")),
              Password(
                Id(:verifyPassword),
                Opt(:hstretch),
                _("&Verify Password")
              )
            ),
            HBox(
              HWeight(1, TextEntry(Id(:filename), _("&File Name:"))),
              VBox(
                Label(""),
                PushButton(Id(:browse), Opt(:notify), Label.BrowseButton)
              )
            ),
            VSpacing(1),
            HBox(
              PushButton(Id(:ok), Opt(:default, :key_F10), Label.OKButton),
              HStretch(),
              PushButton(Id(:cancel), Opt(:key_F9), Label.AbortButton)
            ), # push button label
            VSpacing(1)
          ),
          HSpacing(2)
        )
      )

      ui = nil
      UI.ChangeWidget(Id(:PK12password), :Enabled, false)
      UI.ChangeWidget(Id(:verifyPassword), :Enabled, false)
      begin
        ui = Convert.to_symbol(UI.UserInput)

        kindmap = {
          :PEM_CERT        => "PEM_CERT",
          :PEM_KEY         => "PEM_KEY",
          :PEM_ENCKEY      => "PEM_ENCKEY",
          :PEM_CERT_KEY    => "PEM_CERT_KEY",
          :PEM_CERT_ENCKEY => "PEM_CERT_ENCKEY",
          :DER_CERT        => "DER_CERT",
          :PKCS12          => "PKCS12",
          :PKCS12_CHAIN    => "PKCS12_CHAIN"
        }

        kind = Ops.get(
          kindmap,
          Convert.to_symbol(UI.QueryWidget(Id(:rb), :CurrentButton)),
          ""
        )

        filtermap = {
          :PEM_CERT        => "*.pem *.crt *",
          :PEM_KEY         => "*.pem *.key *",
          :PEM_ENCKEY      => "*.pem *.key *",
          :PEM_CERT_KEY    => "*.pem *.crt *",
          :PEM_CERT_ENCKEY => "*.pem *.crt *",
          :DER_CERT        => "*.der *.crt *",
          :PKCS12          => "*.p12 *.crt *",
          :PKCS12_CHAIN    => "*.p12 *.crt *"
        }

        filterString = Ops.get(
          filtermap,
          Convert.to_symbol(UI.QueryWidget(Id(:rb), :CurrentButton)),
          "*"
        )

        if kind == "PKCS12" || kind == "PKCS12_CHAIN"
          UI.ChangeWidget(Id(:PK12password), :Enabled, true)
          UI.ChangeWidget(Id(:verifyPassword), :Enabled, true)
        else
          UI.ChangeWidget(Id(:PK12password), :Enabled, false)
          UI.ChangeWidget(Id(:verifyPassword), :Enabled, false)
        end

        if ui == :browse
          name = selectFile(true, filterString, "Export to ...")
          UI.ChangeWidget(Id(:filename), :Value, name) if name != nil
        end

        if ui == :ok
          # export to file
          if (kind == "PKCS12" || kind == "PKCS12_CHAIN") &&
              UI.QueryWidget(Id(:PK12password), :Value) !=
                UI.QueryWidget(Id(:verifyPassword), :Value)
            Popup.Error(_("New passwords do not match."))
            ui = :again
          end

          filename = Convert.to_string(UI.QueryWidget(Id(:filename), :Value))
          if Builtins.size(filename) == 0
            Popup.Error(_("File name required."))
            ui = :again
          end

          if ui == :ok
            ret = nil
            if kind == "PKCS12" || kind == "PKCS12_CHAIN"
              ret = Convert.to_string(
                YaPI::CaManagement.ExportCA(
                  {
                    "caName"          => _CAname,
                    "caPasswd"        => getPassword(_CAname),
                    "exportFormat"    => kind,
                    "destinationFile" => filename,
                    "P12Password"     => UI.QueryWidget(
                      Id(:PK12password),
                      :Value
                    )
                  }
                )
              )
            else
              ret = Convert.to_string(
                YaPI::CaManagement.ExportCA(
                  {
                    "caName"          => _CAname,
                    "caPasswd"        => getPassword(_CAname),
                    "exportFormat"    => kind,
                    "destinationFile" => filename
                  }
                )
              )
            end
            Builtins.y2milestone(
              "ExportCA(%1) return %2",
              {
                "caName"          => _CAname,
                "exportFormat"    => kind,
                "destinationFile" => filename
              },
              ret
            )
            if ret == nil || ret != "1"
              showErrorCaManagement
              ui = :again
            else
              Popup.Message(_("CA saved to file."))
            end
          end
        end
      end until Builtins.contains([:ok, :cancel], ui)
      UI.CloseDialog

      nil
    end

    # Dialog for exporting CRL to file
    # @param [String] CAname
    # @return true ( success )
    def exportCRLtoFile(_CAname)
      UI.OpenDialog(
        Opt(:decorated),
        HBox(
          HSpacing(2),
          VBox(
            VSpacing(1),
            # popup window header
            Heading(_("Export CRL to File")),
            VSpacing(1),
            Frame(
              _("Export Format"),
              RadioButtonGroup(
                Id(:rb),
                VBox(
                  Left(
                    RadioButton(Id(:PEM), Opt(:notify), _("&PEM Format"), true)
                  ),
                  Left(RadioButton(Id(:DER), Opt(:notify), _("&DER Format")))
                )
              )
            ),
            HBox(
              HWeight(1, TextEntry(Id(:filename), _("&File Name:"))),
              VBox(
                Label(""),
                PushButton(Id(:browse), Opt(:notify), Label.BrowseButton)
              )
            ),
            VSpacing(1),
            HBox(
              PushButton(Id(:ok), Opt(:default, :key_F10), Label.OKButton),
              HStretch(),
              PushButton(Id(:cancel), Opt(:key_F9), Label.AbortButton)
            ), # push button label
            VSpacing(1)
          ),
          HSpacing(2)
        )
      )

      ui = nil
      begin
        ui = Convert.to_symbol(UI.UserInput)

        kindmap = { :PEM => "PEM", :DER => "DER" }

        filtermap = { :PEM => "*.pem *.crt *", :DER => "*.der *.crt *" }

        filterString = Ops.get(
          filtermap,
          Convert.to_symbol(UI.QueryWidget(Id(:rb), :CurrentButton)),
          "*"
        )

        kind = Ops.get(
          kindmap,
          Convert.to_symbol(UI.QueryWidget(Id(:rb), :CurrentButton)),
          ""
        )

        if ui == :browse
          name = selectFile(true, filterString, "Export to ...")
          UI.ChangeWidget(Id(:filename), :Value, name) if name != nil
        end

        if ui == :ok
          # export to file

          filename = Convert.to_string(UI.QueryWidget(Id(:filename), :Value))
          if Builtins.size(filename) == 0
            Popup.Error(_("File name required."))
            ui = :again
          else
            ret = nil
            ret = Convert.to_string(
              YaPI::CaManagement.ExportCRL(
                {
                  "caName"          => _CAname,
                  "caPasswd"        => getPassword(_CAname),
                  "exportFormat"    => kind,
                  "destinationFile" => filename
                }
              )
            )

            Builtins.y2milestone(
              "ExportCRL(%1) return %2",
              {
                "caName"          => _CAname,
                "exportFormat"    => kind,
                "destinationFile" => filename
              },
              ret
            )
            if ret == nil || ret != "1"
              showErrorCaManagement
              ui = :again
            else
              Popup.Message(_("CRL saved to file."))
            end
          end
        end
      end until Builtins.contains([:ok, :cancel], ui)
      UI.CloseDialog

      nil
    end

    # Dialog for exporting Certificate to file
    # @param [String] CAname, certificate
    # @return true ( success )
    def exportCertificateToFile(_CAname, certificate)
      UI.OpenDialog(
        Opt(:decorated),
        HBox(
          HSpacing(2),
          VBox(
            VSpacing(1),
            # popup window header
            Heading(_("Export Certificate to File")),
            VSpacing(1),
            Frame(
              _("Export Format"),
              RadioButtonGroup(
                Id(:rb),
                VBox(
                  Left(
                    RadioButton(
                      Id(:PEM_CERT),
                      Opt(:notify),
                      _("&Only the Certificate in PEM Format"),
                      true
                    )
                  ),
                  Left(
                    RadioButton(
                      Id(:PEM_KEY),
                      Opt(:notify),
                      _("Only the Key &Unencrypted in PEM Format")
                    )
                  ),
                  Left(
                    RadioButton(
                      Id(:PEM_ENCKEY),
                      Opt(:notify),
                      _("Only the &Key Encrypted in PEM Format")
                    )
                  ),
                  Left(
                    RadioButton(
                      Id(:PEM_CERT_KEY),
                      Opt(:notify),
                      _("Ce&rtificate and the Key Unencrypted in PEM Format")
                    )
                  ),
                  Left(
                    RadioButton(
                      Id(:PEM_CERT_ENCKEY),
                      Opt(:notify),
                      _("C&ertificate and the Key Encrypted in PEM Format")
                    )
                  ),
                  Left(
                    RadioButton(
                      Id(:DER_CERT),
                      Opt(:notify),
                      _("&Certificate in DER Format")
                    )
                  ),
                  Left(
                    RadioButton(
                      Id(:PKCS12),
                      Opt(:notify),
                      _("Cer&tificate and the Key in PKCS12 Format")
                    )
                  ),
                  Left(
                    RadioButton(
                      Id(:PKCS12_CHAIN),
                      Opt(:notify),
                      _("&Like PKCS12 and Include the CA Chain")
                    )
                  )
                )
              )
            ),
            Password(
              Id(:keyPassword),
              Opt(:hstretch),
              _("Certificate &Password:")
            ),
            HBox(
              Password(Id(:PK12password), Opt(:hstretch), _("&New Password")),
              Password(
                Id(:verifyPassword),
                Opt(:hstretch),
                _("&Verify Password")
              )
            ),
            HBox(
              HWeight(1, TextEntry(Id(:filename), _("&File Name:"))),
              VBox(
                Label(""),
                PushButton(Id(:browse), Opt(:notify), Label.BrowseButton)
              )
            ),
            VSpacing(1),
            HBox(
              PushButton(Id(:ok), Opt(:default, :key_F10), Label.OKButton),
              HStretch(),
              PushButton(Id(:cancel), Opt(:key_F9), Label.AbortButton)
            ), # push button label
            VSpacing(1)
          ),
          HSpacing(2)
        )
      )

      ui = nil
      UI.ChangeWidget(Id(:PK12password), :Enabled, false)
      UI.ChangeWidget(Id(:verifyPassword), :Enabled, false)
      begin
        ui = Convert.to_symbol(UI.UserInput)

        kindmap = {
          :PEM_CERT        => "PEM_CERT",
          :PEM_KEY         => "PEM_KEY",
          :PEM_ENCKEY      => "PEM_ENCKEY",
          :PEM_CERT_KEY    => "PEM_CERT_KEY",
          :PEM_CERT_ENCKEY => "PEM_CERT_ENCKEY",
          :DER_CERT        => "DER_CERT",
          :PKCS12          => "PKCS12",
          :PKCS12_CHAIN    => "PKCS12_CHAIN"
        }

        kind = Ops.get(
          kindmap,
          Convert.to_symbol(UI.QueryWidget(Id(:rb), :CurrentButton)),
          ""
        )

        filtermap = {
          :PEM_CERT        => "*.pem *.crt *",
          :PEM_KEY         => "*.pem *.key *",
          :PEM_ENCKEY      => "*.pem *.key *",
          :PEM_CERT_KEY    => "*.pem *.crt *",
          :PEM_CERT_ENCKEY => "*.pem *.crt *",
          :DER_CERT        => "*.der *.crt *",
          :PKCS12          => "*.p12 *.crt *",
          :PKCS12_CHAIN    => "*.p12 *.crt *"
        }

        filterString = Ops.get(
          filtermap,
          Convert.to_symbol(UI.QueryWidget(Id(:rb), :CurrentButton)),
          "*"
        )


        if kind == "PKCS12" || kind == "PKCS12_CHAIN"
          UI.ChangeWidget(Id(:PK12password), :Enabled, true)
          UI.ChangeWidget(Id(:verifyPassword), :Enabled, true)
        else
          UI.ChangeWidget(Id(:PK12password), :Enabled, false)
          UI.ChangeWidget(Id(:verifyPassword), :Enabled, false)
        end

        if ui == :browse
          name = selectFile(true, filterString, "Export to ...")
          UI.ChangeWidget(Id(:filename), :Value, name) if name != nil
        end

        if ui == :ok
          # export to file

          if (kind == "PKCS12" || kind == "PKCS12_CHAIN") &&
              UI.QueryWidget(Id(:PK12password), :Value) !=
                UI.QueryWidget(Id(:verifyPassword), :Value)
            Popup.Error(_("New passwords do not match."))
            ui = :again
          end

          filename = Convert.to_string(UI.QueryWidget(Id(:filename), :Value))
          if Builtins.size(filename) == 0
            Popup.Error(_("File name required."))
            ui = :again
          end

          if ui == :ok
            ret = nil
            if kind == "PKCS12" || kind == "PKCS12_CHAIN"
              ret = Convert.to_string(
                YaPI::CaManagement.ExportCertificate(
                  {
                    "caName"          => _CAname,
                    "caPasswd"        => getPassword(_CAname),
                    "certificate"     => certificate,
                    "keyPasswd"       => UI.QueryWidget(
                      Id(:keyPassword),
                      :Value
                    ),
                    "exportFormat"    => kind,
                    "destinationFile" => filename,
                    "P12Password"     => UI.QueryWidget(
                      Id(:PK12password),
                      :Value
                    )
                  }
                )
              )
            else
              ret = Convert.to_string(
                YaPI::CaManagement.ExportCertificate(
                  {
                    "caName"          => _CAname,
                    "caPasswd"        => getPassword(_CAname),
                    "certificate"     => certificate,
                    "keyPasswd"       => UI.QueryWidget(
                      Id(:keyPassword),
                      :Value
                    ),
                    "exportFormat"    => kind,
                    "destinationFile" => filename
                  }
                )
              )
            end
            Builtins.y2milestone(
              "ExportCertificate(%1) return %2",
              {
                "caName"          => _CAname,
                "certificate"     => certificate,
                "exportFormat"    => kind,
                "destinationFile" => filename
              },
              ret
            )
            if ret == nil || ret != "1"
              showErrorCaManagement
              ui = :again
            else
              Popup.Message(_("Certificate saved to file."))
            end
          end
        end
      end until Builtins.contains([:ok, :cancel], ui)
      UI.CloseDialog

      nil
    end


    # importCertificateFromDisk() - Importing certificate from disk
    # @return success
    def importCertificateFromDisk
      password = ""
      success = false

      contents = VBox(
        VSpacing(1),
        HBox(
          HWeight(1, TextEntry(Id(:filename), _("&File Name:"))),
          VBox(
            Label(""),
            PushButton(Id(:browse), Opt(:notify), Label.BrowseButton)
          )
        ),
        VSpacing(1),
        Password(Id(:password), Opt(:hstretch), _("&Password:")),
        VSpacing(1)
      )

      # help text 1/3
      help_text = _(
        "<p><b><big>Importing Common Server Certificate (PKCS12 + CA Chain Format)\n from Disk:</big></b> Select one file name and press <b>Next</b> to continue.</p>\n"
      )
      # help text 2/3
      help_text = Ops.add(
        help_text,
        _(
          "Import a server certificate and corresponding CA and copy them to a place where other YaST modules look for such a common certificate."
        )
      )

      # help text 3/3
      help_text = Ops.add(
        help_text,
        _("<p><b>Password:</b><br>\nCertificate password</p>\n")
      )

      Wizard.CreateDialog
      Wizard.SetDesktopTitleAndIcon("ca_mgm")
      Wizard.SetContents(
        _("Importing Common Certificate from Disk"),
        contents,
        help_text,
        true,
        true
      )

      Wizard.RestoreBackButton
      Wizard.RestoreAbortButton

      ret = :again
      while ret == :again
        success = false
        ret = UI.UserInput

        if ret == :browse
          name = selectFile(false, "*.p12", "Import from ...")
          UI.ChangeWidget(Id(:filename), :Value, name) if name != nil
          ret = :again
        end

        if ret == :next
          # reading certificate from disk
          filename = Convert.to_string(UI.QueryWidget(Id(:filename), :Value))
          if Builtins.size(filename) == 0
            Popup.Error(_("File name required."))
            ret = :again
          else
            password = Convert.to_string(UI.QueryWidget(Id(:password), :Value))

            UI.BusyCursor
            UI.OpenDialog(VBox(Label(_("Importing certificate..."))))

            yapiret = YaPI::CaManagement.ImportCommonServerCertificate(
              { "passwd" => password, "inFile" => filename }
            )
            Builtins.y2milestone(
              "ImportCommonServerCertificate(%1) return %2",
              filename,
              yapiret
            )
            if yapiret == nil || !yapiret
              showErrorCaManagement
              ret = :again
            else
              Popup.Message(_("Certificate has been imported."))
              success = true
            end
            UI.CloseDialog
          end
        end
      end

      Wizard.CloseDialog
      success
    end


    # exportCommonServerCertificate() - Exporting common server certificate to the local
    #                                   machine
    # @param CA Name, certificate, common name of the certificate
    # @return success
    def exportCommonServerCertificate(_CAname, certificate, commonName)
      success = false
      check = YaPI::CaManagement.Verify(
        {
          "caName"          => _CAname,
          "caPasswd"        => getPassword(_CAname),
          "certificate"     => certificate,
          "disableCRLcheck" => "1",
          "purpose"         => "sslserver"
        }
      )
      # Checking, if the certificate is a server certificate
      if check == nil || !check
        if !Popup.ContinueCancelHeadline(
            # To translators: ContinueCancel Popup headline
            _("Common Server Certificate"),
            # To translators: ContinueCancel Popup
            _("This is not a server certificate. Continue?")
          )
          return true
        end
      end

      # evaluate if the common name of the server certificate is the hostname
      retmap = Convert.to_map(
        SCR.Execute(path(".target.bash_output"), "/bin/hostname --long", {})
      )
      Builtins.y2milestone("Hostname :%1", retmap)
      if commonName != strip(Ops.get_string(retmap, "stdout", ""))
        # check if hostname is in Subject Alt Name
        ret = Convert.to_map(
          YaPI::CaManagement.ReadCertificate(
            {
              "caName"      => _CAname,
              "caPasswd"    => getPassword(_CAname),
              "certificate" => certificate,
              "type"        => "parsed"
            }
          )
        )
        opensslExtentions = Ops.get_map(ret, "OPENSSL_EXTENSIONS", {})
        found = false
        Builtins.foreach(
          Convert.convert(
            Ops.get(opensslExtentions, "X509v3 Subject Alternative Name", []),
            :from => "list",
            :to   => "list <string>"
          )
        ) do |entry|
          if Builtins.issubstring(
              entry,
              strip(Ops.get_string(retmap, "stdout", ""))
            )
            Builtins.y2milestone(
              "Found hostname(%1) in Subject Alternative Name (%2)",
              strip(Ops.get_string(retmap, "stdout", "")),
              entry
            )
            found = true
          end
        end
        if !found
          errorString = Builtins.sformat(
            _(
              "The common name of the certificate (%1) is not the name of\u00B7\n" +
                "the server (%2).\n" +
                "This certificate might be not practical as a common server certificate.\n"
            ),
            commonName,
            strip(Ops.get_string(retmap, "stdout", ""))
          )
          details = _(
            "The hostname of this server (command: hostname --long) have to match \neither the common name of the certificate (CN) or on of the values in subject alternative names."
          )
          Popup.WarningDetails(errorString, details)
        end
      end

      UI.OpenDialog(
        Opt(:decorated),
        HBox(
          HSpacing(2),
          VBox(
            VSpacing(1),
            # popup window header
            Heading(_("Exporting as Common Server Certificate")),
            VSpacing(1),
            Password(
              Id(:keyPassword),
              Opt(:hstretch),
              _("Certificate &Password:")
            ),
            VSpacing(1),
            HBox(
              PushButton(Id(:ok), Opt(:default, :key_F10), Label.OKButton),
              HStretch(),
              PushButton(Id(:cancel), Opt(:key_F9), Label.AbortButton)
            ), # push button label
            VSpacing(1)
          ),
          HSpacing(2)
        )
      )

      ui = nil
      begin
        ui = Convert.to_symbol(UI.UserInput)
        password = Convert.to_string(UI.QueryWidget(Id(:keyPassword), :Value))
        if ui == :ok
          # export to common certificate
          UI.BusyCursor
          UI.OpenDialog(VBox(Label(_("Exporting certificate..."))))
          filename = Ops.add(
            Convert.to_string(SCR.Read(path(".target.tmpdir"))),
            "/commonCertificate"
          )

          ret = Convert.to_string(
            YaPI::CaManagement.ExportCertificate(
              {
                "caName"          => _CAname,
                "caPasswd"        => getPassword(_CAname),
                "certificate"     => certificate,
                "keyPasswd"       => password,
                "exportFormat"    => "PKCS12_CHAIN",
                "destinationFile" => filename,
                "P12Password"     => password
              }
            )
          )

          Builtins.y2milestone(
            "ExportCertificate(%1) return %2",
            {
              "caName"          => _CAname,
              "certificate"     => certificate,
              "exportFormat"    => "PKCS12_CHAIN",
              "destinationFile" => filename
            },
            ret
          )
          if ret == nil || ret != "1"
            showErrorCaManagement
            ui = :again
          else
            yapiret = YaPI::CaManagement.ImportCommonServerCertificate(
              { "passwd" => password, "inFile" => filename }
            )
            Builtins.y2milestone(
              "ImportCommonServerCertificate(%1) return %2",
              filename,
              yapiret
            )
            if yapiret == nil || !yapiret
              showErrorCaManagement
              ui = :again
            else
              Popup.Message(
                _("Certificate has been written as common server certificate.")
              )
              success = true
            end
          end
          UI.CloseDialog
        end
      end until Builtins.contains([:ok, :cancel], ui)
      UI.CloseDialog

      success
    end


    # importRequestFromDisk() - Importing request from disk
    # @param [String] CaName
    # @return success
    def importRequestFromDisk(_CaName)
      success = false

      UI.OpenDialog(
        Opt(:decorated),
        HBox(
          HSpacing(2),
          VBox(
            VSpacing(1),
            Heading(_("Import Request from Disk")),
            VSpacing(1),
            HBox(
              HWeight(2, TextEntry(Id(:filename), _("&File Name:"))),
              HWeight(
                1,
                VBox(
                  Label(""),
                  PushButton(Id(:browse), Opt(:notify), Label.BrowseButton)
                )
              )
            ),
            VSpacing(1),
            HBox(
              PushButton(Id(:ok), Opt(:default, :key_F10), Label.OKButton),
              HStretch(),
              PushButton(Id(:cancel), Opt(:key_F9), Label.AbortButton)
            ), # push button label
            VSpacing(1)
          )
        )
      )




      ret = :again
      while ret == :again
        success = false
        ret = UI.UserInput

        if ret == :browse
          name = selectFile(false, "*.pem *.req *.csr *.der", "Import from ...")
          UI.ChangeWidget(Id(:filename), :Value, name) if name != nil
          ret = :again
        end

        if ret == :ok
          # reading certificate from disk
          filename = Convert.to_string(UI.QueryWidget(Id(:filename), :Value))
          if Builtins.size(filename) == 0
            Popup.Error(_("File name required."))
            ret = :again
          else
            extention = ""
            if Builtins.substring(filename, Builtins.findlastof(filename, ".")) == ".pem" ||
                Builtins.substring(filename, Builtins.findlastof(filename, ".")) == ".req" ||
                Builtins.substring(filename, Builtins.findlastof(filename, ".")) == ".csr"
              extention = "PEM"
            end
            if Builtins.substring(filename, Builtins.findlastof(filename, ".")) == ".der"
              extention = "DER"
            end

            if extention == ""
              Popup.Error(_("File format not valid. Use PEM or DER files."))
              ret = :again
            else
              UI.BusyCursor
              UI.OpenDialog(VBox(Label(_("Importing request..."))))

              yapiret = YaPI::CaManagement.ImportRequest(
                {
                  "caName"       => _CaName,
                  "caPasswd"     => getPassword(_CaName),
                  "inFile"       => filename,
                  "importFormat" => extention
                }
              )
              Builtins.y2milestone(
                "ImportRequest(%1) return %2",
                filename,
                yapiret
              )
              if yapiret == nil
                showErrorCaManagement
                ret = :again
              else
                Popup.Message(_("Request has been imported."))
                success = true
              end
              UI.CloseDialog
            end
          end
        end
      end
      UI.CloseDialog
      success
    end


    # importCAFromDisk() - Importing CA from disk
    # @return success
    def importCAFromDisk
      success = false

      UI.OpenDialog(
        Opt(:decorated),
        HBox(
          HSpacing(2),
          VBox(
            VSpacing(1),
            Heading(_("Import CA from Disk")),
            TextEntry(Id(:caName), _("&CA Name:")),
            HBox(
              HWeight(2, TextEntry(Id(:pathCert), _("&Path of CA Certificate"))),
              HWeight(
                1,
                VBox(
                  Label(""),
                  PushButton(Id(:browseCert), Opt(:notify), Label.BrowseButton)
                )
              )
            ),
            HBox(
              HWeight(2, TextEntry(Id(:pathKey), _("&Path of Key"))),
              HWeight(
                1,
                VBox(
                  Label(""),
                  PushButton(Id(:browseKey), Opt(:notify), Label.BrowseButton)
                )
              )
            ),
            Password(Id(:passKey), Opt(:hstretch), _("&Key Password")),
            VSpacing(1),
            HBox(
              PushButton(Id(:ok), Opt(:default, :key_F10), Label.OKButton),
              HStretch(),
              PushButton(Id(:cancel), Opt(:key_F9), Label.AbortButton)
            ), # push button label
            VSpacing(1)
          )
        )
      )




      ret = :again
      while ret == :again
        success = false
        ret = UI.UserInput

        if ret == :browseCert
          name = selectFile(false, "*.pem *.crt", "Import from ...")
          UI.ChangeWidget(Id(:pathCert), :Value, name) if name != nil
          ret = :again
        end

        if ret == :browseKey
          name = selectFile(false, "*.pem *.key", "Import from ...")
          UI.ChangeWidget(Id(:pathKey), :Value, name) if name != nil
          ret = :again
        end

        if ret == :ok
          # reading CA from disk

          caCertificate = Convert.to_string(
            UI.QueryWidget(Id(:pathCert), :Value)
          )
          caKey = Convert.to_string(UI.QueryWidget(Id(:pathKey), :Value))
          caPasswd = Convert.to_string(UI.QueryWidget(Id(:passKey), :Value))
          caName = Convert.to_string(UI.QueryWidget(Id(:caName), :Value))
          if Builtins.size(caCertificate) == 0
            # Error popup
            Popup.Error(_("Path to certificate file required."))
            ret = :again
          elsif Builtins.size(caKey) == 0
            # Error popup
            Popup.Error(_("Path of the private key required."))
            ret = :again
          elsif Builtins.size(caPasswd) == 0
            # Error popup
            Popup.Error(
              _(
                "Key Password is required. \nIt must be the password for the encrypted key or a new one in case of a not encrypted key."
              )
            )
            ret = :again
          elsif Builtins.size(caName) == 0
            # Error popup
            Popup.Error(_("CA name required."))
            ret = :again
          end

          if ret == :ok
            UI.BusyCursor
            UI.OpenDialog(VBox(Label(_("Importing request..."))))

            yapiret = YaPI::CaManagement.ImportCA(
              {
                "caName"        => caName,
                "caCertificate" => caCertificate,
                "caKey"         => caKey,
                "caPasswd"      => caPasswd
              }
            )
            Builtins.y2milestone(
              "ImportRequest(%1,%2,%3, <passwd>) return %4",
              caName,
              caCertificate,
              caKey,
              yapiret
            )
            if yapiret == nil
              showErrorCaManagement
              ret = :again
            else
              # Error popup
              Popup.Message(_("CA has been imported."))
              success = true
            end
            UI.CloseDialog
          end
        end
      end
      UI.CloseDialog
      success
    end


    def getHostIPs
      ret = {}

      ip_addresses = Builtins.splitstring(
        Ops.get_string(
          Convert.convert(
            SCR.Execute(
              path(".target.bash_output"),
              "ip -f inet -o addr show scope global | awk '{print $4}' | awk -F / '{print $1}' | tr '\n' ','"
            ),
            :from => "any",
            :to   => "map <string, any>"
          ),
          "stdout",
          ""
        ),
        ","
      )

      ip6_addresses = Builtins.splitstring(
        Ops.get_string(
          Convert.convert(
            SCR.Execute(
              path(".target.bash_output"),
              "ip -f inet6 -o addr show scope global | awk '{print $4}' | awk -F / '{print $1}' | tr '\n' ','"
            ),
            :from => "any",
            :to   => "map <string, any>"
          ),
          "stdout",
          ""
        ),
        ","
      )

      Builtins.foreach(ip6_addresses) do |ip6|
        if ip6 != "::1" && ip6 != ""
          ip_addresses = Builtins.add(ip_addresses, ip6)
        end
      end
      Builtins.foreach(ip_addresses) do |ip|
        # skip localhost addresses
        if ip != "127.0.0.1" && ip != "127.0.0.2" && ip != ""
          # add the IP address
          Ops.set(ret, ip, "IP")

          # first ask the DNS server about the name for this IP address
          hostnames = Builtins.splitstring(
            Ops.get_string(
              Convert.convert(
                SCR.Execute(
                  path(".target.bash_output"),
                  Builtins.sformat(
                    "dig +noall +answer +time=2 +tries=1 -x %1 | awk '{print $5}' | sed 's/\\.$//'| tr '\n' '|'",
                    ip
                  )
                ),
                :from => "any",
                :to   => "map <string, any>"
              ),
              "stdout",
              ""
            ),
            "|"
          )

          found = false
          Builtins.foreach(hostnames) do |hname|
            if hname != "" && Builtins.findfirstof(hname, ".") != nil
              # add the names
              found = true
              Ops.set(ret, hname, "DNS")
            end
          end
          # If not found, ask the hosts file about the IP address
          if !found
            hostnames2 = Builtins.splitstring(
              Ops.get_string(
                Convert.convert(
                  SCR.Execute(
                    path(".target.bash_output"),
                    Builtins.sformat(
                      "getent hosts %1 | awk '{print $2}' | sed 's/\\.$//'| tr '\n' '|'",
                      ip
                    )
                  ),
                  :from => "any",
                  :to   => "map <string, any>"
                ),
                "stdout",
                ""
              ),
              "|"
            )

            Builtins.foreach(hostnames2) do |hname|
              if hname != "" && Builtins.findfirstof(hname, ".") != nil
                # add the names
                Ops.set(ret, hname, "DNS")
              end
            end
          end
        end
      end
      Builtins.y2milestone("getHostIPs return: %1", ret)
      deep_copy(ret)
    end
  end
end
